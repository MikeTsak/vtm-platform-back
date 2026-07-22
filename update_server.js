const fs = require('fs');
let code = fs.readFileSync('server.js', 'utf8');

const matches = [...code.matchAll(/const fileBlob = new Blob\(\[([^\]]+)\]\);/g)];
console.log(`Found ${matches.length} Blob wrappers.`);

for (const match of [...matches].reverse()) {
    const bufferVar = match[1];
    const index = match.index;
    const nextUpload = code.indexOf('imageClient.uploadImage(fileBlob,', index);
    
    if (nextUpload !== -1 && nextUpload - index < 500) {
        code = code.substring(0, index) + `// const fileBlob = new Blob([${bufferVar}]);` + code.substring(index + match[0].length);
        const newUploadIdx = code.indexOf('imageClient.uploadImage(fileBlob,', index);
        code = code.substring(0, newUploadIdx) + `imageClient.uploadImage(${bufferVar},` + code.substring(newUploadIdx + 'imageClient.uploadImage(fileBlob,'.length);
    }
}

fs.writeFileSync('server.js', code);
console.log('Done!');
