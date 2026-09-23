-- =====================================================================
-- 0025_feeding_failure_reason — manual/production equivalent
-- =====================================================================
--
-- Hand-run version of migrations/list/0025_feeding_failure_reason.js, for
-- phpMyAdmin. Run it BEFORE deploying/restarting the backend: the server
-- applies pending migrations on boot, and step 4 below records this one as
-- applied so the boot (and the Admin > Master "Run pending" button) skip it.
--
-- Safe to re-run: step 1 fails harmlessly with "Duplicate column" if the
-- column already exists (just continue with step 2); steps 2-3 only fill
-- rows that are still NULL; step 4 uses INSERT IGNORE.

-- 1. Column for the stored "how the hunt went wrong" line.
ALTER TABLE feedings ADD COLUMN `failure_reason` TEXT DEFAULT NULL AFTER `outcome`;

-- 2. Past failures that raised a domain incident reuse its text.
UPDATE feedings f
JOIN domain_incidents di ON di.feeding_id = f.id
SET f.failure_reason = di.flavor_text
WHERE f.failure_reason IS NULL AND di.flavor_text IS NOT NULL;

-- 3. Every other past failure gets a random line for its predator type
--    (same lines as back/data/predatorFlavor.js).
UPDATE feedings
SET failure_reason = CASE predator_type
  WHEN 'Alleycat' THEN ELT(FLOOR(1 + RAND() * 5),
      'A busted lip and a stolen wallet. The hunter was gone before anyone got a look at their face, and forgot to lick the wound closed.',
      'Bruised knuckles, a torn collar, and a very confused mugging victim who swears their attacker''s eyes flashed red.',
      'They hit too hard and left too fast, and the alley still has the blood spatter to prove it.',
      'A night-shift cabbie watched the whole thing from across the street and wrote down every detail.',
      'The victim fought back harder than expected, and the screaming brought half the block to their windows.')
  WHEN 'Bagger' THEN ELT(FLOOR(1 + RAND() * 5),
      'A hospital fridge came up short a unit of blood, and the paperwork doesn''t add up.',
      'They paid cash, asked too many questions, and left a black-market contact spooked enough to talk.',
      'Someone''s been going through the blood bank''s waste bins, and they weren''t subtle about it.',
      'A courier on the take got cold feet and handed the delivery log to hospital security.',
      'The cooler bag was left behind in a taxi, still full, with a pharmacy label on the side.')
  WHEN 'Cleaver' THEN ELT(FLOOR(1 + RAND() * 5),
      'A ''friend'' keeps coming back looking pale and forgetful, and people are starting to notice the pattern.',
      'They got too comfortable feeding from the same source twice in one week, and someone saw the second bite mark.',
      'The cover story cracked when a loved one asked one question too many, and there was no good answer.',
      'A relative found the mark''s diary, full of entries about blackouts after every visit.',
      'The mark''s doctor ran bloodwork, found chronic anemia with no cause, and started asking about their visitors.')
  WHEN 'Consensualist' THEN ELT(FLOOR(1 + RAND() * 5),
      'They were upfront with a stranger about what they are, and the stranger wasn''t as discreet as promised.',
      'A ''clinic volunteer'' left behind a signed consent form with just enough detail to raise eyebrows.',
      'They told someone the truth to get their blood, and that someone told two friends.',
      'A willing donor fainted on the walk home, and the ER staff want to know who drew so much blood.',
      'A donor posted about the ''vampire thing'' in a private group chat that is no longer very private.')
  WHEN 'Farmer' THEN ELT(FLOOR(1 + RAND() * 5),
      'A gutted stray and a trail of prints leading nowhere human, but a dog walker saw the hunter crouched over it.',
      'They left an animal carcass somewhere it shouldn''t be, and somebody with a camera phone found it first.',
      'The local shelter''s missing another animal, and this time there were witnesses to the chase.',
      'A farmer found livestock drained dry and white in the field and called in the local vet and the press.',
      'Animal control traced a string of drained strays back to the same rooftop.')
  WHEN 'Osiris' THEN ELT(FLOOR(1 + RAND() * 5),
      'A fan got too close backstage and remembers hands that were too cold and too strong.',
      'They fed from an admirer in a hallway, and a phone was recording from the wrong angle at the wrong time.',
      'Too many followers have noticed the same pale, shaky person leaving the greenroom lately.',
      'A devoted follower posted a gushing thread about the ''blood blessing'', and it is gathering attention.',
      'An ex-follower walked out of the circle angry and went straight to a journalist with the rituals.')
  WHEN 'Sandman' THEN ELT(FLOOR(1 + RAND() * 5),
      'They left a window open on the way out, and this time the sleeper woke up mid-feed.',
      'A break-in with nothing stolen except a few hours of somebody''s blood, and a groggy witness who half-remembers a face.',
      'They got sloppy with the lock and left scratch marks a security camera caught in full.',
      'The sleeper had a baby monitor on, and the recording caught every second of the visit.',
      'A smart doorbell logged a figure walking in at 3 AM and out ten minutes later, with nothing taken.')
  WHEN 'Scene Queen' THEN ELT(FLOOR(1 + RAND() * 5),
      'They fed from someone in their own scene, and now the whispers are spreading faster than they can manage them.',
      'A fellow regular at the club noticed the same pale hanger-on drain three people of energy in one night.',
      'They got recognized by the wrong person, at the wrong after-party.',
      'A rival in the scene started a rumour about the ''thing'' in the VIP room, and people believe it.',
      'A promoter pulled the CCTV after one too many guests collapsed in the same back room.')
  WHEN 'Siren' THEN ELT(FLOOR(1 + RAND() * 5),
      'A one-night stand woke up with a headache, a bite mark that won''t heal right, and a lot of questions.',
      'They got careless mid-seduction, and a jilted partner caught them mid-bite and isn''t staying quiet about it.',
      'Someone''s ex is telling anyone who''ll listen about the bite marks that wouldn''t stop bleeding.',
      'The date left early, sober enough to remember the cold skin and no heartbeat under their hand.',
      'A hotel housekeeper found blood on the pillows and a guest who could barely stand.')
  WHEN 'Extortionist' THEN ELT(FLOOR(1 + RAND() * 5),
      'A ''protection client'' stopped paying in favors and started talking to the wrong people about what the collector really wanted.',
      'They leaned on someone too hard, and now there''s a bruised, furious mortal telling their story to anyone who''ll listen.',
      'The coercion left a trail: a threatening voicemail traced right back to them.',
      'The target recorded the whole shakedown on a phone left running in a jacket pocket.',
      'A debtor fled to a cousin on the force, and the story of the ''collector'' is now in a police report.')
  WHEN 'Graverobber' THEN ELT(FLOOR(1 + RAND() * 5),
      'A disturbed grave and a missing body were bad enough, and a groundskeeper is now asking very pointed questions.',
      'They fed on a mourner at a wake and left the mourner pale enough that the funeral home called an ambulance.',
      'Fresh dirt under their nails and a body missing from cold storage, and the morgue attendant isn''t buying the excuse.',
      'A cemetery''s new motion-triggered floodlights lit up the whole hunt for the night guard.',
      'The funeral director noticed an embalmed body missing fluids that were never drained on the books.')
  WHEN 'Roadside Killer' THEN ELT(FLOOR(1 + RAND() * 5),
      'A hitchhiker never made it to their stop, and a trucker at the last rest stop remembers the car.',
      'They fed and dumped too close to a truck stop with working cameras.',
      'A missing person report just named a stretch of highway they''ve hunted on before.',
      'A dashcam in a passing car caught the pull-over and the plate on the shoulder.',
      'The pick-up got away into the headlights of a highway patrol car and pointed straight back.')
  WHEN 'Grim Reaper' THEN ELT(FLOOR(1 + RAND() * 5),
      'A hospice nurse noticed a ''visitor'' who was never on the sign-in sheet, feeding from a dying patient.',
      'A patient''s vitals crashed right after an unlogged visit, and the staff are asking who let the visitor in.',
      'They lingered too long at a bedside, and a family member walked in at exactly the wrong moment.',
      'A night nurse found puncture marks on a patient who died with nothing logged in the chart.',
      'The palliative ward''s badge scanner logged a visitor card that belongs to no one on staff.')
  WHEN 'Montero' THEN ELT(FLOOR(1 + RAND() * 5),
      'The ''random mugging'' their retainers staged left a witness who noticed it wasn''t random at all.',
      'A drive planned too cleanly, and someone clocked the same car circling the block three times before the attack.',
      'One of their retainers talked, and now the wrong ears know how the hunt was arranged.',
      'The beaters drove the prey straight past a late-night kebab shop full of witnesses.',
      'The hunting party got loud, and a neighbour called in a ''pack'' chasing someone through the streets.')
  WHEN 'Pursuer' THEN ELT(FLOOR(1 + RAND() * 5),
      'They stalked their mark for too many nights in a row, and the mark finally called the police about the ''watcher.''',
      'A neighbor noticed the same face outside the same window one too many nights.',
      'Their patience slipped for one night, and the target got a good enough look to describe them.',
      'The mark found a pattern in the sightings and posted a photo of their ''stalker'' online.',
      'A private investigator hired by the mark''s family is now following the follower.')
  WHEN 'Trapdoor' THEN ELT(FLOOR(1 + RAND() * 5),
      'A ''guest'' left the den more shaken than seduced, and now they''re telling people what they saw inside.',
      'Someone got out of the den faster than expected and left the door wide open behind them.',
      'A trespasser meant as prey got away, and took photos of the inside of the lair with them.',
      'A missing-person flyer went up with the den''s address as the last known location.',
      'A delivery driver who came to the wrong door saw someone inside who could not leave.')
  ELSE ELT(FLOOR(1 + RAND() * 5),
      'Something about the hunt went wrong, and it left a trail that''s already reaching the wrong ears.',
      'A witness saw more than they should have, and they haven''t stopped talking about it.',
      'The scene left behind wasn''t clean, and someone in the neighborhood noticed.',
      'The victim remembered more than they should have, and a friend is taking notes.',
      'A camera no one thought about caught enough of the hunt to raise questions.')
END
WHERE failure_reason IS NULL AND status = 'resolved'
  AND outcome IN ('bestial_failure','failure','messy_critical');

-- 4. Mark the migration as applied so the server doesn't run it again.
INSERT IGNORE INTO schema_migrations (name) VALUES ('0025_feeding_failure_reason');
