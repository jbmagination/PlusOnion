import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
let filterlistsFolder = new URL('../filterlists', import.meta.url);
await fs.readdir(filterlistsFolder, (err, data) => { 
    if (err) throw err;
    makeChecksums(data);
});

async function makeChecksums(filterlists) {
    console.log('[ Making checksums ]')
    filterlists.forEach(filterlist => {
        if (filterlist.endsWith('.sig')) return;
        const fullFilePath = filterlistsFolder.toString().replace('file:///', '') + '/' + filterlist;
        var checksumLine = false;
        var existingChecksum = undefined;
        const file = fs.readFileSync(fullFilePath, { encoding: 'utf8' });
        const lines = file.split('\n').filter(Boolean);
        lines.length = 50;
        var noChecksumFile = file;
        lines.forEach((line) => {
            if (line.startsWith('! Checksum:')) {
                checksumLine = true;
                existingChecksum = line.replace('! Checksum:', '').trim();
                console.log('Found existing checksum ' + existingChecksum + ' on filterlist ' + filterlist)
                noChecksumFile = file.replace(`${line}\n`, '');
            }
        })

        var newChecksum = Buffer.from(createHash('md5').update(noChecksumFile).digest()).toString('base64').replaceAll('=', '');
        var newData = false;
        if (checksumLine) {
            if (existingChecksum == newChecksum) {
                console.log('File unchanged, no new checksum to be added\n');
                return
            }
            newData = file.replace(`! Checksum: ${existingChecksum}`, `! Checksum: ${newChecksum}`);
        } else newData = `! Checksum: ${newChecksum}\n${file}`;
        if (newData) {
            console.log('Adding checksum ' + newChecksum + ' to ' + filterlist);
            fs.writeFileSync(fullFilePath, newData, { encoding: 'utf8' });
        }
        console.log('\n');
    });
    signFiles(filterlists);
}

async function signFiles(filterlists) {
    console.log('[ Signing files ]')
    const privateKey = filterlistsFolder.toString().replace('file:///', '') + '/../private.asc';
    if (!(fs.existsSync(privateKey))) {
        console.log('No private key found, skipping');
        return
    }
    filterlists.forEach(filterlist => {
        const fullFilePath = filterlistsFolder.toString().replace('file:///', '') + '/' + filterlist;
        if (filterlist.endsWith('.sig')) return;
        if (fs.existsSync(`${fullFilePath}.sig`)) fs.rmSync(`${fullFilePath}.sig`);
        console.log('Signing file ' + filterlist)
        spawn('gpg', ['--detach-sig', '--sign', '--output', `${fullFilePath}.sig`, fullFilePath])
    })
    console.log('\n[ All done ]')
}