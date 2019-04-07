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

const RAW_DATA_PATH = path.join(DATA_PATH, 'rawData.csv');
const ZIP_PATH = path.join(DATA_PATH, 'zipFiles');
const UNZIPPED_PATH = path.join(DATA_PATH, 'unzippedFiles');
const LOG_RESULTS_PATH = path.join(RESULTS_PATH, 'logResults');
const LOG_ERR_PATH = path.join(RESULTS_PATH, 'errors');

const LOGFILE_PATH = path.resolve(path.join(DATA_PATH, 'loglist.json'));

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
		return;
	}
	return `https://www.sec.gov/Archives/edgar/data/${sanitizedCik}/${accession}.txt`;
}

async function sendRequest(url, mode, params) {
	let data;
	let response;
	let retries = 0;
	while (retries < 10) {
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
	return response;
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

function hashFn(ip, cik, accession) {
	return `${ip}_${cik}_${accession}`;
}

function csvStringToLogObject(csv) {
	const logInfo = parse(csv, {
		columns: true,
		skip_empty_lines: true,
	});
	const map = {};
	const result = [];
	logInfo.forEach(({ accession, cik, ip}) => {
		const hashKey = hashFn(ip, cik, accession);
		if (map[hashKey]) {
			return;
		}
		map[hashKey] = true;
		result.push({
			accession,
			cik,
			ip: ip.replace(/[^\d\.]/g, 0),
		})
	});
	debugger;
	return result;
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
	return csvStringToLogObject(csv)
}

function readRawDataFile() {
	const csv = fs.readFileSync(RAW_DATA_PATH, 'utf-8');
	return csvStringToLogObject(csv);
}

async function lookupIp(ip) {
	const url = makeIpLookupUrl(ip);
	const response = await sendRequest(url, 'GET');
	const ipInfo = await response.json();
	if (ipInfo.status !== 'success') {
		return;
	}
	return {
		ipAddr: ip,
		city: ipInfo.city,
		country: ipInfo.country,
		org: ipInfo.org,
		region: ipInfo.region,
	};
}

async function lookupSecInfo(cik, accession) {
	const url = makeSecUrl(cik, accession);
	if (!url) {
		return;
	}
	const response = await sendRequest(url, 'GET');
	const data = await response.text();
	const parsedSecInfo = edgarParser.parseSecInfo(data);
	return {
		formType: parsedSecInfo.submissionType,
		formUrl: url,
	}
}

function createRawDataStream() {
	return fs.createWriteStream(RAW_DATA_PATH, { flags: 'a' });
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

function saveDatumToRawData(stream, entries, append) {
	const csvString = objectToCsvString(entries, RAW_COLUMN_NAMES, append);
	stream.write(csvString);
}

function saveProcessedLogResults(stream, name, entries = [], append = false) {
	const columnNames = COLUMN_NAMES.map(c => (
		MAP_VARIABLE_TO_COLUMN_NAME[c]
	));

	// const records = [];
	// if (!append) {
	// 	records.push(columnNames);
	// }
	// entries.forEach(entry => {
	// 	const record = COLUMN_NAMES.map(c => entry[c]);
	// 	records.push(record);
	// });
	const csvString = objectToCsvString(entries, COLUMN_NAMES, append, columnNames);
	stream.write(csvString);
}

function saveErrors(stream, name, errArr) {
	const stringifiedErrArr = JSON.stringify(errArr) + '\n';
	stream.write(stringifiedErrArr);
}

function deleteDownloadedFiles(name) {
	fs.unlink(makeZipfilePath(name), () => {});
	fs.unlink(makeUnzipfilePath(name), () => {});
}

async function processLogEntry({ cik, accession, ip }) {
	const ipInfo = await lookupIp(ip);
	const secInfo = await lookupSecInfo(cik, accession);

	return {
		...ipInfo,
		...secInfo,
	}
}

function getPercentage(index, total) {
	return ((index / total) * 100).toFixed(4);
}

function setupProgress(name) {
	// process.stdout.write(`${name}: `);

	const intervalId = setInterval(() => process.stdout.write('.'), 2000)

	// const writeProgress = (index, total, efficient = true) => {
	// 	// Don't do this calculation every time as it's a waste of resources
	// 	if (efficient && index % 10 !== 0) {
	// 		return;
	// 	}
	// 	const progress = parseInt(getPercentage(index, total));
	// 	if (progress > 100) {
	// 		// process.stdout.write('\n');
	// 		clearInterval(intervalId);
	// 		return;
	// 	}
	// 	// if (progress % 5 === 0) {
	// 	// 	process.stdout.write(String(progress));
	// 	// }
	// }

	return intervalId;
}

async function processInBatch(
	{ fileStream, errorStream },
	promiseFnArr,
	batchSize,
	name,
){
	let currentIndex = 0;
	// const allResults = [];
	// const allErrors = [];
	const intervalId = setupProgress(name);

	async function helper(thisBatch) {
		const requests = thisBatch.map(p => promiseThrottle.add(p));
		return Promise.when(requests);
	}
	// console.log('    ');
	const arrLen = promiseFnArr.length;
	for (let i = 0; i < arrLen; i += batchSize) {
		// writeProgress(i, promiseFnArr.length);
		readline.cursorTo(process.stdout, 4);
		readline.clearLine(process.stdout, 1);
		process.stdout.write(`${i}/${arrLen} (${getPercentage(i, arrLen)}%)`)

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

		// allErrors.push(...errArr);
		// allResults.push(...filteredArr);
	}
	clearInterval(intervalId);
	// return { allResults, allErrors };
}

// async function processRawDatum({ url, name }) {
//
// }

async function processLogFile({ name, url }) {
	const downloadedFilePath = await downloadFile(url, name);
	const logInfo = await unzipLogFile(downloadedFilePath, name);
	deleteDownloadedFiles(name);

	return logInfo;

	// const uniqLogs = _.uniqBy(logInfo, entry => entry.ip);
	//
	// return uniqLogs;
	// const entryArrPromises = [];
	// const logLen = logInfo.length;
	// for (let i = 0; i < logLen; i++) {
	// 	entryArrPromises.push(() => processLogEntry(logInfo[i]));
	// }
	// const streams = createLogStreams(name);
	//
	// const results = await processInBatch(streams, entryArrPromises, 100, name);
	// streams.fileStream.end();
	// streams.errorStream.end();
	// const entryResults = results.allResults;
	// const entryErrors = results.allErrors;
	//
	// saveProcessedLogResults(name, entryResults);
	// saveErrors(name, entryErrors);
}


async function getRawData(force) {
	if (fs.existsSync(RAW_DATA_PATH) && !force) {
		// Providee the file
		return readRawDataFile();
	}
	// if (fs.existsSync(RAW_DATA_PATH)) {
	// 	fs.unlinkSync(RAW_DATA_PATH);
	// }
	const { list } = await populateLogList(true);
	if (!list) {
		console.error('Could not populate log list. Exiting');
		return;
	}
	const listLen = list.length;
	console.log('Building Raw Data')
	const stream = createRawDataStream();
	for (let i = 0; i < listLen; i++) {
		// if (i < 1527) {
		// 	continue;
		// }
		readline.cursorTo(process.stdout, 0);
		readline.clearLine(process.stdout, 0);
		process.stdout.write(`Processing #${i} (of ${listLen}): ${list[i].name}`);

		const uniqLogs = await processLogFile(list[i]);
		await saveDatumToRawData(stream, uniqLogs, i !== 0);

	}
	console.log('\nProcessed');
	stream.end();

	// Sanitize the raw file to remove all the uniq entries
	const uniqRawData = readRawDataFile();
	fs.unlinkSync(RAW_DATA_PATH);
	const stream2 = createRawDataStream();
	saveDatumToRawData(stream2, uniqRawData, true);
	stream2.end();

	return readRawDataFile();
}

async function main() {
	const before = Date.now();
	console.log('Start Time: ', new Date(before));

	const rawData = await getRawData(true);
	debugger;

	const after = Date.now();
	console.log('Before', before, 'After', after, 'Duration', after-before);
	debugger;
}

main();
