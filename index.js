const parse = require('csv-parse/lib/sync')
const stringify = require('csv-stringify/lib/sync')
const extract = require('extract-zip')
const fs = require('fs');
const _ = require('lodash');
const fetch = require("node-fetch");
const path = require('path');
const readline = require('readline');
const { promisify } = require('util');

const EdgarParser = require('./EdgarParser.js').EdgarParser;
const edgarParser = new EdgarParser();

const extractZip = promisify(extract);

const PromiseThrottle = require('promise-throttle');
const promiseThrottle = new PromiseThrottle({
  requestsPerSecond: 10,
  promiseImplementation: Promise,
});

// Update promise.all to complete even with rejection
const reflect = (promise) => promise
	.then((result) => ({ result, status: 'fulfilled' }))
	.catch((error) => ({ error, status: 'rejected' }));
Promise.when = (promiseList) =>
	Promise.all(promiseList.map(reflect));

const DATA_PATH = path.join(__dirname, 'data');
const RESULTS_PATH = path.join(__dirname, 'results');

// const RAW_DATA_PATH = path.join(DATA_PATH, 'rawData.csv');
const ZIP_PATH = path.join(DATA_PATH, 'zipFiles');
const UNZIPPED_PATH = path.join(DATA_PATH, 'unzippedFiles');
const LOG_RESULTS_PATH = path.join(RESULTS_PATH, 'logResults');
const LOG_ERR_PATH = path.join(RESULTS_PATH, 'errors');

const LOGFILE_PATH = path.resolve(path.join(DATA_PATH, 'loglist.json'));
// const GLOBAL_IP_ACCESSION_PATH = path.resolve(path.join(DATA_PATH, 'globalIpAccessionMap.json'))
const SEC_CACHE_PATH = path.resolve(path.join(DATA_PATH), 'secCache.json');
const IP_CACHE_PATH = path.resolve(path.join(DATA_PATH), 'ipCache.json');
const SEC_CACHE_BAK_PATH = path.resolve(path.join(DATA_PATH), 'secCache_bak.json');
const IP_CACHE_BAK_PATH = path.resolve(path.join(DATA_PATH), 'ipCache_bak.json');
const LAST_LOG_PATH = path.resolve(path.join(DATA_PATH), 'lastLog.txt');

const RAW_COLUMN_NAMES =
	['ip', 'accession', 'cik'];

const COLUMN_NAMES =
	['ipAddr', 'org', 'region', 'city', 'country', 'formType', 'formUrl'];
const MAP_VARIABLE_TO_COLUMN_NAME = {
	ipAddr: 'IP Address',
	org: 'Organization',
	region: 'Region',
	city: 'City',
	country: 'Country',
	formType: 'SEC Form Type',
	formUrl: 'SEC Form URL',
}

let globalIpAccessionMap = new Set();
let ipCache = new Map();
let secCache = new Map();
let ipCacheChanged = false;
let secCacheChanged = false;
let lastLog = 0;
let saveProgress = () => {};

if (fs.existsSync(SEC_CACHE_PATH)) {
	let map;
	try {
		map = fs.readFileSync(SEC_CACHE_PATH, 'utf-8');
		map = JSON.parse(map);
	} catch (e) {
		map = undefined;
	}
	secCache = new Map(map);
	fs.renameSync(SEC_CACHE_PATH, SEC_CACHE_BAK_PATH);
}
if (fs.existsSync(IP_CACHE_PATH)) {
	let map;
	try {
		map = fs.readFileSync(IP_CACHE_PATH, 'utf-8');
		map = JSON.parse(map);
	} catch (e) {
		map = undefined;
	}
	ipCache = new Map(map);
	fs.renameSync(IP_CACHE_PATH, IP_CACHE_BAK_PATH);
}
if (fs.existsSync(LAST_LOG_PATH)) {
	let lastLogFromFile = fs.readFileSync(LAST_LOG_PATH, 'utf-8');
	lastLog = Number(lastLogFromFile);
}

if (!fs.existsSync(DATA_PATH)) {
	fs.mkdirSync(DATA_PATH);
}
if (!fs.existsSync(RESULTS_PATH)) {
	fs.mkdirSync(RESULTS_PATH);
}
if (!fs.existsSync(ZIP_PATH)) {
	fs.mkdirSync(ZIP_PATH);
}
if (!fs.existsSync(UNZIPPED_PATH)) {
	fs.mkdirSync(UNZIPPED_PATH);
}
if (!fs.existsSync(LOG_RESULTS_PATH)) {
	fs.mkdirSync(LOG_RESULTS_PATH);
}
if (!fs.existsSync(LOG_ERR_PATH)) {
	fs.mkdirSync(LOG_ERR_PATH);
}

function makeZipfilePath(name) {
	return path.resolve(path.join(ZIP_PATH, `${name}.zip`));
}

function makeUnzipfilePath(name) {
	return path.resolve(path.join(UNZIPPED_PATH, `${name}.csv`));
}

function makeLogResultsFilePath(name) {
	return path.resolve(path.join(LOG_RESULTS_PATH, `${name}.csv`));
}

function makeLogErrorsFilePath(name) {
	return path.resolve(path.join(LOG_ERR_PATH, `${name}.json`));
}

function makeIpLookupUrl(ip) {
	return `https://extreme-ip-lookup.com/json/${ip}`;
}

function makeSecUrl(cik, accession) {
	const match = cik.match(/(.*)\./);
	const sanitizedCik = match && match[1];
	if (!sanitizedCik) {
		sanitizedCik = cik;
	}
	return `https://www.sec.gov/Archives/edgar/data/${sanitizedCik}/${accession}.txt`;
}

function makeSaveProgress(logIdToSave) {
	fs.writeFileSync(LAST_LOG_PATH, logIdToSave);
	return (ipCacheChanged, secCacheChanged) => {
		if (ipCacheChanged) {
			fs.writeFileSync(IP_CACHE_PATH, JSON.stringify(Array.from(ipCache)))
		}
		if (secCacheChanged) {
			fs.writeFileSync(SEC_CACHE_PATH, JSON.stringify(Array.from(secCache)))
		}
	}
}

let currentY = 0;
function logToOutput(log, xPos, yPos) {
	const yOffset = yPos - currentY;
	readline.moveCursor(process.stdout, 0, yOffset);
	readline.cursorTo(process.stdout, xPos);
	readline.clearLine(process.stdout, 0);
	process.stdout.write(log);
	currentY = yPos;
}

async function sendRequest(url, mode, params) {
	return new Promise(async(resolve, reject) => {
		const timeoutId = setTimeout(() => {
			console.log(`${url}: Timed out after 60 seconds`);
			reject(`${url}: Timed out after 60 seconds`);
		}, 60000);

		let data;
		let response;
		let retries = 0;
		while (retries < 5) {
			let isSuccessful = true;
			try {
				response = await fetch(url, {
					method: mode,
					headers: {},
					body: JSON.stringify(params)
				});
			} catch(err) {
				console.error('Request Error: ', err.message);
				console.log(`Retrying #${retries + 1}`)
				isSuccessful = false;
			}
			if (isSuccessful) {
				break;
			}
			retries += 1;
		}
		clearInterval(timeoutId);
		resolve(response);
	})
}

async function populateLogList(force) {
	if (fs.existsSync(LOGFILE_PATH) && !force) {
		const data = fs.readFileSync(LOGFILE_PATH, 'utf-8');
		let parsedData;
		try {
			parsedData = JSON.parse(data);
		} catch (err) {
			console.log(err);
		}
		if (parsedData) {
			return parsedData;
		}
	}
	const LOG_LIST_URL = 'https://www.sec.gov/files/EDGAR_LogFileData_thru_Jun2017.html';
	let logListHtml;
	try {
		const response = await sendRequest(LOG_LIST_URL, 'GET');
		logListHtml = await response.text();
	} catch {
		// Do nothing. If it failed it failed
	}
	if (!logListHtml) {
		return {};
	}
	const logItems = logListHtml
		.split(/\n/)
		.slice(8, -2)
		.map(i => i.replace(' ', ''))
		.map(i => 'https://' + i);
	const parsedList = {};
	const list = [];
	logItems.forEach(item => {
		const match = item.match(/www.sec.gov\/dera\/data\/Public-EDGAR-log-file-data\/(.*)\.zip/)
		if (!match || !match[1]) {
			return;
		}
		const parts = match[1].split('/');
		if (parts.length === 0) {
			return;
		}
		const year = parts[0];
		const quarter = parts[1];
		const fileName = parts[2];

		_.set(parsedList, [year, quarter, fileName], item);
		list.push({ name: fileName, url: item });
	});
	const result = { list, parsed: parsedList }
	fs.writeFileSync(LOGFILE_PATH, JSON.stringify(result));
	return result;
}

async function downloadFile(url, name) {
	const filePath = makeZipfilePath(name);
	const res = await sendRequest(url, 'GET');
	const fileStream = fs.createWriteStream(filePath);
	await new Promise((resolve, reject) => {
		res.body.pipe(fileStream);
		res.body.on("error", (err) => {
			reject(err);
		});
		fileStream.on("finish", function() {
			resolve();
		});
	});
	return filePath;
}

function hashFn(accession, cik, ip) {
	return `${accession}_${cik}_${ip}`;
}

function csvStringToLogObject(csv) {
	const logInfo = parse(csv, {
		columns: true,
		skip_empty_lines: true,
	});
	const results = [];
	logInfo.forEach(({ accession, cik, ip}) => {
		const hashKey = hashFn(accession, cik, ip);
		if (globalIpAccessionMap.has(hashKey)) {
			return;
		}
		globalIpAccessionMap.add(hashKey);
		results.push({
			accession,
			cik,
			ip: ip.replace(/[^\d\.]/g, 0),
		});
	});
	return results;
}

async function unzipLogFile(filePath, name) {
	let err;
	let csv;
	try {
		err = await extractZip(filePath, { dir: UNZIPPED_PATH });
		csv = fs.readFileSync(makeUnzipfilePath(name), 'utf-8');
	} catch (err) {
		console.error(err);
	}
	return csvStringToLogObject(csv);
}

async function lookupIp(ip) {
	const url = makeIpLookupUrl(ip);
	if (ipCache.has(url)) {
		return ipCache.get(url);
	}
	const response = await sendRequest(url, 'GET');
	const ipInfo = await response.json();
	if (ipInfo.status !== 'success') {
		return;
	}
	const data = {
		ipAddr: ip,
		city: ipInfo.city,
		country: ipInfo.country,
		org: ipInfo.org,
		region: ipInfo.region,
	};
	ipCacheChanged = true;
	ipCache.set(url, data);
	return data;
}

async function lookupSecInfo(cik, accession) {
	const url = makeSecUrl(cik, accession);
	if (!url) {
		return;
	}
	if (secCache.has(url)) {
		return secCache.get(url);
	}
	const response = await sendRequest(url, 'GET');
	const data = await response.text();
	const formType = edgarParser.parseFormType(data);
	const parsedData = {
		formType: formType,
		formUrl: url,
	}
	secCacheChanged = true;
	secCache.set(url, parsedData);
	return parsedData;
}

function createLogStreams(name) {
	const logFileStream =
		fs.createWriteStream(makeLogResultsFilePath(name), { flags: 'a' });
	const errFileStream =
		fs.createWriteStream(makeLogErrorsFilePath(name), { flags: 'a' });
	return { fileStream: logFileStream, errorStream: errFileStream };
}

function objectToCsvString(entries, columnArray, append, header) {
	const records = [];
	if (!append) {
		records.push(header || columnArray);
	}
	entries.forEach(entry => {
		const record = columnArray.map(c => entry[c]);
		records.push(record);
	})
	return stringify(records);
}

function saveProcessedLogResults(stream, name, entries = [], append = false) {
	const columnNames = COLUMN_NAMES.map(c => (
		MAP_VARIABLE_TO_COLUMN_NAME[c]
	));

	const csvString = objectToCsvString(entries, COLUMN_NAMES, append, columnNames);
	stream.write(csvString);
}

function saveErrors(stream, name, errArr) {
	const stringifiedErrArr = JSON.stringify(errArr) + '\n';
	stream.write(stringifiedErrArr);
}

function deleteDownloadedFiles(name) {
	fs.unlinkSync(makeZipfilePath(name));
	fs.unlinkSync(makeUnzipfilePath(name));
}

function canUseAllCache({ cik, accession, ip }) {
	const ipUrl = makeIpLookupUrl(ip);
	const secUrl = makeSecUrl(cik, accession);

	return ipCache.has(ipUrl) && secCache.has(secUrl);
}

async function processLogEntry({ cik, accession, ip }) {
	const ipInfoPromise = lookupIp(ip);
	const secInfoPromise = lookupSecInfo(cik, accession);

	return Promise.when([ipInfoPromise, secInfoPromise]).then((results) => {
		const ipInfo = results[0].result || {};
		const secInfo = results[1].result || {};
		return {
			...ipInfo,
			...secInfo,
		}
	})
}

function getPercentage(index, total) {
	return ((index / total) * 100).toFixed(4);
}

function setupProgress() {
	let secondsRunning = 0;
	let intervalId;
	intervalId = setInterval(() => {
		secondsRunning += 2;
		if (secondsRunning > 60) {
			// Progress is running for more than 60 seconds. Save progress
			saveProgress(true, true);
			process.stdout.write('Algorithm is stuck. Restart algorithm!!!')
			clearInterval(intervalId);
		}
		process.stdout.write('.')
	}, 2000);

	return intervalId;
}

async function processInBatch(
	{ fileStream, errorStream },
	promiseFnArr,
	batchSize,
	name,
){
	let currentIndex = 0;

	async function helper(thisBatch) {
		const requests = thisBatch.map(p => p());
		return Promise.when(requests);
	}
	const arrLen = promiseFnArr.length;
	if (!arrLen) {
		logToOutput('No entries', 4, 2);
	}
	for (let i = 0; i < arrLen; i += batchSize) {
		const intervalId = setupProgress();
		logToOutput(`${i}/${arrLen} (${getPercentage(i, arrLen)}%)`, 4, 2);

		const thisBatch = promiseFnArr.slice(i, i + batchSize);
		const batchResults = await helper(thisBatch);
		const filteredArr = batchResults
			.filter(e => e.status === 'fulfilled')
			.map(e => e.result);
		const errArr = batchResults
			.filter(e => e.status === 'rejected')
			.map(e => e.error);

		saveProcessedLogResults(fileStream, name, filteredArr, i !== 0);
		if (errArr.length !== 0) {
			saveErrors(errorStream, name, errArr);
		}
		clearInterval(intervalId);
	}
}

function makeRequestFunction({ ip, accession, cik }) {
	return () => {
		const isIpCached = ipCache.has(makeIpLookupUrl(ip));
		const isSecCached = secCache.has(makeSecUrl(cik, accession));
		if (!isIpCached && !isSecCached) {
			return promiseThrottle.add(() => processLogEntry({ ip, accession, cik }));
		}
		let ipInfoPromise;
		let secInfoPromise;
		if (isIpCached) {
			secInfoPromise = promiseThrottle.add(() => lookupSecInfo(cik, accession));
			ipInfoPromise = lookupIp(ip);
		} else {
			ipInfoPromise =  promiseThrottle.add(() => lookupIp(ip));
			secInfoPromise = lookupSecInfo(cik, accession);
		}
		return Promise.when([ipInfoPromise, secInfoPromise]).then((results) => {
			const ipInfo = results[0].result || {};
			const secInfo = results[1].result || {};
			return {
				...ipInfo,
				...secInfo,
			}
		});
	}
}

async function processLogFile({ name, url }) {
	const downloadedFilePath = await downloadFile(url, name);
	const logInfo = await unzipLogFile(downloadedFilePath, name);
	deleteDownloadedFiles(name);

	const streams = createLogStreams(name);

	const entryArrData = [];
	const entryArrPromises = [];
	const logLen = logInfo.length;
	for (let i = 0; i < logLen; i++) {
		if (canUseAllCache(logInfo[i])) {
			const result = await processLogEntry(logInfo[i]);
			entryArrData.push(result);
		} else {
			entryArrPromises.push(makeRequestFunction(logInfo[i]));
		}
	}
	logToOutput('Processing new requests', 4, 1);
	await processInBatch(streams, entryArrPromises, 50, name);

	logToOutput('Processing cached requests', 4, 1);
	logToOutput(`Total: ${entryArrData.length}`, 4, 2);

	const intervalId = setupProgress();
	saveProcessedLogResults(streams.fileStream, name, entryArrData, entryArrPromises.length !== 0);
	clearInterval(intervalId);

	streams.fileStream.end();
	streams.errorStream.end();
}

async function main() {
	const before = Date.now();
	console.log('Start Time: ', new Date(before));

	const { list } = await populateLogList(true);
	if (!list) {
		console.error('Could not populate log list. Exiting');
		return;
	}
	const listLen = list.length;
	console.log('Starting Processing');
	for (let i = 0; i < listLen; i++) {
		globalIpAccessionMap = new Set();
		ipCacheChanged = false;
		secCacheChanged = false;
		saveProgress = makeSaveProgress(i);

		if (i < lastLog) {
			continue;
		}
		logToOutput(`Processing #${i} (of ${listLen}): ${list[i].name}`, 0, 0)
		await processLogFile(list[i]);

		logToOutput('Saving caches', 0, 1)
		saveProgress(ipCacheChanged, secCacheChanged);
		// if (ipCacheChanged) {
		// 	fs.writeFileSync(IP_CACHE_PATH, JSON.stringify(Array.from(ipCache)))
		// }
		// if (secCacheChanged) {
		// 	fs.writeFileSync(SEC_CACHE_PATH, JSON.stringify(Array.from(secCache)))
		// }

	}
	const after = Date.now();
	console.log('Before', before, 'After', after, 'Duration', after-before);
	debugger;
}

main();
