// data/predatorFlavor.js
//
// In-universe "how the trail was noticed" flavor lines, one randomly chosen
// per domain incident (a Failure/Bestial Failure/Messy Critical feeding roll
// in a domain someone else owns). Three per predator type, matching the
// hunting style described in front/src/data/predator_types.js. Rendered once
// at confirm time and stored verbatim on the domain_incidents row — never
// regenerated, so an incident always reads the same way on every view.
//
// 'Blood Leech' and 'Tithe Collector' aren't included — those predator types
// can't use the automated Feeding roll at all (see predatorHuntingPools.js).

const PREDATOR_FLAVOR = {
  Alleycat: [
    "A busted lip and a stolen wallet. He left before anyone got a look at his face, and forgot to lick the wound closed.",
    "Bruised knuckles, a torn collar, and a very confused mugging victim who swears their attacker's eyes flashed red.",
    "He hit too hard and left too fast, and the alley still has the blood spatter to prove it.",
  ],
  Bagger: [
    "A hospital fridge came up short a unit of blood, and the paperwork doesn't add up.",
    "He paid cash, asked too many questions, and left a black-market contact spooked enough to talk.",
    "Someone's been going through the blood bank's waste bins, and they weren't subtle about it.",
  ],
  Cleaver: [
    "A 'friend' keeps coming back looking pale and forgetful, and people are starting to notice the pattern.",
    "He got too comfortable feeding from the same source twice in one week, and someone saw the second bite mark.",
    "The cover story cracked when a loved one asked one question too many, and he didn't have a good answer.",
  ],
  Consensualist: [
    "He was upfront with a stranger about what he is, and the stranger wasn't as discreet as promised.",
    "A 'clinic volunteer' left behind a signed consent form with just enough detail to raise eyebrows.",
    "He told someone the truth to get their blood, and that someone told two friends.",
  ],
  Farmer: [
    "A gutted stray and a trail of prints leading nowhere human, but a dog walker saw him crouched over it.",
    "He left an animal carcass somewhere it shouldn't be, and somebody with a camera phone found it first.",
    "The local shelter's missing another animal, and this time there were witnesses to the chase.",
  ],
  Osiris: [
    "A fan got too close backstage and remembers hands that were too cold and too strong.",
    "He fed from an admirer in a hallway, and a phone was recording from the wrong angle at the wrong time.",
    "Too many followers have noticed the same pale, shaky person leaving his greenroom lately.",
  ],
  Sandman: [
    "He left a window open on his way out, and this time the sleeper woke up mid-feed.",
    "A break-in with nothing stolen except a few hours of somebody's blood, and a groggy witness who half-remembers a face.",
    "He got sloppy with the lock and left scratch marks a security camera caught in full.",
  ],
  'Scene Queen': [
    "He fed from someone in his own scene, and now the whispers are spreading faster than he can manage them.",
    "A fellow regular at the club noticed the same pale hanger-on drain three people of energy in one night.",
    "He got recognized by the wrong person, at the wrong after-party.",
  ],
  Siren: [
    "A one-night stand woke up with a headache, a bite mark that won't heal right, and a lot of questions.",
    "He got careless mid-seduction, and a jilted partner caught him mid-bite and isn't staying quiet about it.",
    "Someone's ex is telling anyone who'll listen about the bite marks that wouldn't stop bleeding.",
  ],
  Extortionist: [
    "A 'protection client' stopped paying in favors and started talking to the wrong people about what he really wanted.",
    "He leaned on someone too hard, and now there's a bruised, furious mortal telling his story to anyone who'll listen.",
    "The coercion left a trail: a threatening voicemail traced right back to him.",
  ],
  Graverobber: [
    "A disturbed grave and a missing body were bad enough, and a groundskeeper is now asking very pointed questions.",
    "He fed on a mourner at a wake and left them pale enough that the funeral home called an ambulance.",
    "Fresh dirt under his nails and a body missing from cold storage, and the morgue attendant isn't buying his excuse.",
  ],
  'Roadside Killer': [
    "A hitchhiker never made it to their stop, and a trucker at the last rest stop remembers the car.",
    "He fed and dumped too close to a truck stop with working cameras.",
    "A missing person report just named a stretch of highway he's hunted on before.",
  ],
  'Grim Reaper': [
    "A hospice nurse noticed a 'visitor' who was never on the sign-in sheet, feeding from a dying patient.",
    "A patient's vitals crashed right after an unlogged visit, and the staff are asking who let him in.",
    "He lingered too long at a bedside, and a family member walked in at exactly the wrong moment.",
  ],
  Montero: [
    "The 'random mugging' his retainers staged left a witness who noticed it wasn't random at all.",
    "A drive planned too cleanly, and someone clocked the same car circling the block three times before the attack.",
    "One of his retainers talked, and now the wrong ears know how the hunt was arranged.",
  ],
  Pursuer: [
    "He stalked his mark for too many nights in a row, and the mark finally called the police about the 'watcher.'",
    "A neighbor noticed the same face outside the same window one too many nights.",
    "His patience slipped for one night, and the target got a good enough look to describe him.",
  ],
  Trapdoor: [
    "A 'guest' left his den more shaken than seduced, and now they're telling people what they saw inside.",
    "Someone got out of his den faster than expected and left the door wide open behind them.",
    "A trespasser he meant to feed on got away, and took photos of the inside of his lair with them.",
  ],
};

const GENERIC_FLAVOR = [
  "Something about the hunt went wrong, and it left a trail that's already reaching the wrong ears.",
  "A witness saw more than they should have, and they haven't stopped talking about it.",
  "The scene he left behind wasn't clean, and someone in the neighborhood noticed.",
];

function pickFlavor(predatorType, rng = Math.random) {
  const pool = PREDATOR_FLAVOR[predatorType] || GENERIC_FLAVOR;
  return pool[Math.floor(rng() * pool.length)];
}

module.exports = { PREDATOR_FLAVOR, GENERIC_FLAVOR, pickFlavor };
