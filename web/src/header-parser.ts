// Header parser for JPI EDM files
// Parses the ASCII header section that precedes binary flight data

import type { Config, AlarmLimits, FuelConfig, FlightIndex, Timestamp, ParsedHeader } from './types';

export class HeaderParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HeaderParseError';
  }
}

export class ChecksumError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ChecksumError';
  }
}

const FLIGHT_HEADER_SIZE = 28; // 14 x 16-bit words

export function parseHeader(data: Uint8Array): ParsedHeader {
  const result: ParsedHeader = {
    tailNumber: null,
    config: null,
    alarmLimits: null,
    fuelConfig: null,
    flights: [],
    timestamp: null,
    binaryOffset: 0,
  };

  const decoder = new TextDecoder('ascii');
  let pos = 0;
  let cumulativeOffset = 0; // Track cumulative offset for flight data

  while (pos < data.length) {
    // Find next line ending (CR+LF)
    let lineEnd = -1;
    for (let i = pos; i < data.length - 1; i++) {
      if (data[i] === 0x0D && data[i + 1] === 0x0A) { // \r\n
        lineEnd = i;
        break;
      }
    }

    if (lineEnd === -1) break;

    const lineBytes = data.slice(pos, lineEnd);
    const line = decoder.decode(lineBytes);

    // Header lines start with $
    if (!line.startsWith('$')) break;

    const flightEntry = parseHeaderLine(line, result, cumulativeOffset);
    if (flightEntry) {
      cumulativeOffset += flightEntry.dataLength;
    }

    pos = lineEnd + 2; // Skip past \r\n

    // $L marks end of headers
    if (line.startsWith('$L')) {
      result.binaryOffset = pos;
      break;
    }
  }

  if (result.binaryOffset === 0) {
    throw new HeaderParseError('No $L record found - invalid file format');
  }

  // Now find actual flight positions using signature matching
  findFlightPositions(data, result);

  return result;
}

/**
 * Find actual byte positions for all flights using sequential position calculation.
 *
 * JPI data_words = ceiling(actual_bytes / 2), meaning:
 * - When actual flight length is ODD, data_words * 2 = actual + 1
 * - The discrepancy is ALWAYS 0 or 1 byte, never more
 *
 * Algorithm: For each flight, check expected position AND expected-1 for valid header.
 * This is bounded (exactly 2 positions) rather than arbitrary searching.
 */
function findFlightPositions(data: Uint8Array, result: ParsedHeader): void {
  if (result.flights.length === 0) return;

  const dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let currentPos = result.binaryOffset;

  for (const flight of result.flights) {
    // Check expected position AND expected-1 (handles odd-length flight rounding)
    const foundOffset = findFlightAtPosition(dataView, flight.flightNumber, currentPos);

    if (foundOffset !== null) {
      flight.actualOffset = foundOffset;
      // Move forward by data_words * 2 for next flight's expected position
      currentPos = foundOffset + flight.dataLength;
    } else {
      // actualOffset remains -1 (set in parseFlightIndex)
      // Still advance by expected length for next flight
      currentPos += flight.dataLength;
    }
  }
}

/**
 * Find flight header at expected position, checking both expected AND expected-1.
 * Returns the actual offset if found, or null if not found at either position.
 */
function findFlightAtPosition(
  dataView: DataView,
  flightNumber: number,
  expectedPos: number
): number | null {
  const flightNumHigh = (flightNumber >> 8) & 0xFF;
  const flightNumLow = flightNumber & 0xFF;

  // Check expected position first, then 1 byte before
  // (data_words rounds UP for odd-length flights)
  for (const delta of [0, -1]) {
    const pos = expectedPos + delta;
    if (pos < 0 || pos + FLIGHT_HEADER_SIZE > dataView.byteLength) continue;

    // Check for flight number match (big-endian)
    if (dataView.getUint8(pos) === flightNumHigh &&
        dataView.getUint8(pos + 1) === flightNumLow &&
        isValidFlightHeader(dataView, pos)) {
      return pos;
    }
  }

  return null;
}

/**
 * Validate that a position contains a valid flight header.
 * Checks interval and date/time fields for reasonable values.
 */
function isValidFlightHeader(dataView: DataView, pos: number): boolean {
  // Interval (word 11, bytes 22-23) should be 1-60 seconds
  const interval = dataView.getUint16(pos + 22, false);
  if (interval < 1 || interval > 60) {
    return false;
  }

  // Date (word 12, bytes 24-25): day:5, month:4, year:7
  const dateBits = dataView.getUint16(pos + 24, false);
  const day = dateBits & 0x1F;
  const month = (dateBits >> 5) & 0x0F;
  const year = ((dateBits >> 9) & 0x7F) + 2000;

  if (day < 1 || day > 31 || month < 1 || month > 12 || year < 2000 || year > 2100) {
    return false;
  }

  // Time (word 13, bytes 26-27): secs:5, mins:6, hrs:5
  const timeBits = dataView.getUint16(pos + 26, false);
  const secs = (timeBits & 0x1F) * 2;
  const mins = (timeBits >> 5) & 0x3F;
  const hrs = (timeBits >> 11) & 0x1F;

  if (hrs > 23 || mins > 59 || secs > 59) {
    return false;
  }

  return true;
}

function parseHeaderLine(line: string, result: ParsedHeader, cumulativeOffset: number): FlightIndex | null {
  // Verify checksum
  verifyChecksum(line);

  // Remove checksum suffix (*XX)
  const content = line.replace(/\*[0-9A-Fa-f]{2}$/, '');

  const recordType = content[1];
  const fieldsStr = content.slice(3); // Skip "$X,"
  const fields = fieldsStr.split(',').map(f => f.trim());

  switch (recordType) {
    case 'U':
      result.tailNumber = parseTailNumber(fields);
      break;
    case 'A':
      result.alarmLimits = parseAlarmLimits(fields);
      break;
    case 'C':
      result.config = parseConfig(fields);
      break;
    case 'D': {
      const flightEntry = parseFlightIndex(fields, cumulativeOffset);
      result.flights.push(flightEntry);
      return flightEntry;
    }
    case 'F':
      result.fuelConfig = parseFuelConfig(fields);
      break;
    case 'T':
      result.timestamp = parseTimestamp(fields);
      break;
    case 'P':
    case 'H':
    case 'L':
      // Known but not parsed
      break;
    default:
      // Unknown record type - ignore
      break;
  }
  return null;
}

function verifyChecksum(line: string): void {
  const starIndex = line.indexOf('*');
  if (starIndex === -1) return;

  const content = line.slice(1, starIndex); // Between $ and *
  const expectedHex = line.slice(starIndex + 1, starIndex + 3);
  const expected = parseInt(expectedHex, 16);

  let calculated = 0;
  for (let i = 0; i < content.length; i++) {
    calculated ^= content.charCodeAt(i);
  }

  if (calculated !== expected) {
    throw new ChecksumError(
      `Header checksum mismatch: expected ${expected.toString(16)}, got ${calculated.toString(16)}`
    );
  }
}

function parseTailNumber(fields: string[]): string {
  // Join fields in case tail number contains commas
  return fields.join(',').replace(/\*.*$/, '').trim();
}

function parseAlarmLimits(fields: string[]): AlarmLimits {
  return {
    voltsHigh: parseInt(fields[0]) || 0,
    voltsLow: parseInt(fields[1]) || 0,
    dif: parseInt(fields[2]) || 0,
    cht: parseInt(fields[3]) || 0,
    cld: parseInt(fields[4]) || 0,
    tit: parseInt(fields[5]) || 0,
    oilHigh: parseInt(fields[6]) || 0,
    oilLow: parseInt(fields[7]) || 0,
  };
}

function parseConfig(fields: string[]): Config {
  return {
    model: parseInt(fields[0]) || 0,
    flagsLow: parseInt(fields[1]) || 0,
    flagsHigh: parseInt(fields[2]) || 0,
    unknown1: fields[3] ? parseInt(fields[3]) : undefined,
    unknown2: fields[4] ? parseInt(fields[4]) : undefined,
    unknown3: fields[5] ? parseInt(fields[5]) : undefined,
    unknown4: fields[6] ? parseInt(fields[6]) : undefined,
    unknown5: fields[7] ? parseInt(fields[7]) : undefined,
    unknown6: fields[8] ? parseInt(fields[8]) : undefined,
  };
}

function parseFlightIndex(fields: string[], startOffset: number): FlightIndex {
  const dataWords = parseInt(fields[1]) || 0;
  return {
    flightNumber: parseInt(fields[0]) || 0,
    dataWords,
    dataLength: dataWords * 2,
    startOffset,
    actualOffset: -1, // Will be set by findFlightPositions
  };
}

function parseFuelConfig(fields: string[]): FuelConfig {
  return {
    emptyWarning: parseInt(fields[0]) || 0,
    fullCapacity: parseInt(fields[1]) || 0,
    warningLevel: parseInt(fields[2]) || 0,
    kFactor1: parseInt(fields[3]) || 0,
    kFactor2: parseInt(fields[4]) || 0,
  };
}

function parseTimestamp(fields: string[]): Timestamp {
  return {
    month: parseInt(fields[0]) || 0,
    day: parseInt(fields[1]) || 0,
    year: parseInt(fields[2]) || 0,
    hour: parseInt(fields[3]) || 0,
    minute: parseInt(fields[4]) || 0,
    unknown: fields[5] ? parseInt(fields[5]) : undefined,
  };
}
