// services/format.js
//
// Small pure formatting/date helpers shared across routes. No db, no log, no
// request — safe to import from anywhere and trivially unit-testable.

function formatDate(d) {
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function startOfMonth(d = new Date()) {
  return new Date(d.getFullYear(), d.getMonth(), 1);
}

function endOfMonth(d = new Date()) {
  return new Date(d.getFullYear(), d.getMonth() + 1, 1);
}

// Default downtime feeding action implied by a character's Predator Type.
function feedingFromPredator(pred) {
  const map = {
    Alleycat: 'Violent Hunt',
    Sandman: 'Sleeping Prey',
    Siren: 'Seduction',
    Osiris: 'Cult Feeding',
    Farmer: 'Animal/Bagged',
    Bagger: 'Bagged Blood',
    'Scene Queen': 'Scene Influence',
    Consensualist: 'Consent Feeding',
    Extortionist: 'Blackmail Feeding',
    'Blood Leech': 'Vitae Theft',
  };
  return map[pred] || 'Standard Feeding';
}

module.exports = { formatDate, startOfMonth, endOfMonth, feedingFromPredator };
