function validateRetainerSheet(tier, sheet, isGhoul) {
    if (!sheet) return "Sheet is empty.";

    const attrCounts = { 4: 0, 3: 0, 2: 0, 1: 0, 0: 0 }; // Tier 4: { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0, 0: 0 }
    const skillCounts = { 4: 0, 3: 0, 2: 0, 1: 0 }; // Tier 4: { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0 }
    
    // Total attributes = 9 (Physical, Social, Mental x3)
    let assignedAttrs = 0;
    for (const val of Object.values(sheet.attributes || {})) {
        if (val > 4 || val < 1) return `Invalid attribute level: ${val}`; // Tier 4: val > 5
        attrCounts[val]++;
        assignedAttrs++;
    }
    // Any unassigned attributes are assumed to be 1.
    // /* Tier 4 logic: const baseAttr = tier === 4 ? 2 : 1; attrCounts[baseAttr] += (9 - assignedAttrs); */
    attrCounts[1] += (9 - assignedAttrs);
    
    // Total skills = 27
    let assignedSkills = 0;
    for (const val of Object.values(sheet.skills || {})) {
        if (val > 4 || val < 0) return `Invalid skill level: ${val}`; // Tier 4: val > 5
        if (val > 0) skillCounts[val]++;
        assignedSkills++;
    }
    
    // Advantages/Flaws points
    let advPoints = 0;
    let flawPoints = 0;
    for (const adv of (sheet.advantages || [])) {
        advPoints += (Number(adv.dots) || 0);
    }
    for (const flaw of (sheet.flaws || [])) {
        flawPoints += (Number(flaw.dots) || 0);
    }
    
    // Ghoul disciplines
    let disciplineCount = 0;
    for (const val of Object.values(sheet.disciplines || {})) {
        if (val > 1) return "Retainers can have a maximum of 1 dot in a discipline.";
        if (val === 1) disciplineCount++;
    }

    if (isGhoul && disciplineCount > 1) return "Ghouls can only have 1 dot in exactly one Discipline.";
    if (!isGhoul && disciplineCount > 0) return "Non-ghoul mortals cannot have Disciplines.";

    if (tier === 1) { // Weak Mortal
        if (attrCounts[2] !== 2) return `Tier 1 must have exactly Two attributes at 2. (Found ${attrCounts[2]})`;
        if (attrCounts[1] !== 7) return `Tier 1 must have exactly Seven attributes at 1. (Found ${attrCounts[1]})`;
        
        if (skillCounts[2] !== 3) return `Tier 1 must have exactly Three skills at 2. (Found ${skillCounts[2]})`;
        if (skillCounts[1] !== 5) return `Tier 1 must have exactly Five skills at 1. (Found ${skillCounts[1]})`;
        if (skillCounts[3] > 0 || skillCounts[4] > 0) return "Tier 1 cannot have skills above 2.";
        
        if (advPoints > 0) return "Tier 1 cannot have Advantages.";
        if (flawPoints > 0) return "Tier 1 cannot have Flaws.";
    } 
    else if (tier === 2) { // Average Mortal
        if (attrCounts[3] !== 2) return `Tier 2 must have exactly Two attributes at 3. (Found ${attrCounts[3]})`;
        if (attrCounts[2] !== 3) return `Tier 2 must have exactly Three attributes at 2. (Found ${attrCounts[2]})`;
        if (attrCounts[1] !== 4) return `Tier 2 must have exactly Four attributes at 1. (Found ${attrCounts[1]})`;
        
        if (skillCounts[3] !== 3) return `Tier 2 must have exactly Three skills at 3. (Found ${skillCounts[3]})`;
        if (skillCounts[2] !== 4) return `Tier 2 must have exactly Four skills at 2. (Found ${skillCounts[2]})`;
        if (skillCounts[1] !== 5) return `Tier 2 must have exactly Five skills at 1. (Found ${skillCounts[1]})`;
        if (skillCounts[4] > 0) return "Tier 2 cannot have skills above 3.";
        
        if (advPoints > 3) return `Tier 2 can have up to 3 points in Advantages. (Found ${advPoints})`;
        if (flawPoints > 2) return `Tier 2 can have up to 2 points in Flaws. (Found ${flawPoints})`;
    }
    else if (tier === 3) { // Gifted Mortal
        if (attrCounts[4] !== 1) return `Tier 3 must have exactly One attribute at 4. (Found ${attrCounts[4]})`;
        if (attrCounts[3] !== 2) return `Tier 3 must have exactly Two attributes at 3. (Found ${attrCounts[3]})`;
        if (attrCounts[2] !== 2) return `Tier 3 must have exactly Two attributes at 2. (Found ${attrCounts[2]})`;
        if (attrCounts[1] !== 4) return `Tier 3 must have exactly Four attributes at 1. (Found ${attrCounts[1]})`;
        
        if (skillCounts[4] !== 2) return `Tier 3 must have exactly Two skills at 4. (Found ${skillCounts[4]})`;
        if (skillCounts[3] !== 4) return `Tier 3 must have exactly Four skills at 3. (Found ${skillCounts[3]})`;
        if (skillCounts[2] !== 4) return `Tier 3 must have exactly Four skills at 2. (Found ${skillCounts[2]})`;
        if (skillCounts[1] !== 4) return `Tier 3 must have exactly Four skills at 1. (Found ${skillCounts[1]})`;
        
        if (advPoints > 10) return `Tier 3 can have up to 10 points in Advantages. (Found ${advPoints})`;
        if (flawPoints > 4) return `Tier 3 can have up to 4 points in Flaws. (Found ${flawPoints})`;
    }
    /*
    else if (tier === 4) { // Deadly Mortal
        if (attrCounts[5] !== 2) return `Tier 4 must have exactly Two attributes at 5. (Found ${attrCounts[5]})`;
        if (attrCounts[4] !== 2) return `Tier 4 must have exactly Two attributes at 4. (Found ${attrCounts[4]})`;
        if (attrCounts[3] !== 2) return `Tier 4 must have exactly Two attributes at 3. (Found ${attrCounts[3]})`;
        if (attrCounts[2] !== 3) return `Tier 4 must have exactly Three attributes at 2. (Found ${attrCounts[2]})`;
        if (attrCounts[1] > 0) return `Tier 4 cannot have attributes at 1. (Found ${attrCounts[1]})`;
        
        if (skillCounts[5] !== 1) return `Tier 4 must have exactly One skill at 5. (Found ${skillCounts[5]})`;
        if (skillCounts[4] !== 3) return `Tier 4 must have exactly Three skills at 4. (Found ${skillCounts[4]})`;
        if (skillCounts[3] !== 5) return `Tier 4 must have exactly Five skills at 3. (Found ${skillCounts[3]})`;
        if (skillCounts[2] !== 6) return `Tier 4 must have exactly Six skills at 2. (Found ${skillCounts[2]})`;
        
        if (advPoints > 15) return `Tier 4 can have up to 15 points in Advantages. (Found ${advPoints})`;
        if (flawPoints > 0) return `Tier 4 cannot have Flaws. (Found ${flawPoints})`;
    }
    */

    return null; // Valid
}

module.exports = { validateRetainerSheet };
