// utils/athensTime.js
//
// Europe/Athens wall-clock formatting, pulled out of routes/activity.js and
// routes/comms.js where it was defined twice (byte-for-byte, in one case).

function getAthensHour(dateInput) {
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return 0;
  const hourStr = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Athens',
    hour: '2-digit',
    hour12: false,
  }).format(d);
  const h = parseInt(hourStr, 10);
  return isNaN(h) ? 0 : h;
}

function getAthensDate(dateInput) {
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return '';
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Athens',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(d);
}

function getAthensDayName(dateInput) {
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return '';
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Athens',
    weekday: 'long',
  }).format(d);
}

function getAthensEuDate(dateInput) {
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return '';
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Athens',
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  }).formatToParts(d);
  const day = parts.find(p => p.type === 'day')?.value;
  const month = parts.find(p => p.type === 'month')?.value;
  const year = parts.find(p => p.type === 'year')?.value;
  return `${day}/${month}/${year}`;
}

module.exports = { getAthensHour, getAthensDate, getAthensDayName, getAthensEuDate };
