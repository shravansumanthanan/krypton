const fs = require('fs');
const path = require('path');

describe('Blocklist JSON Parsing', () => {
    let blocklist;

    beforeAll(() => {
        const filePath = path.join(__dirname, '../blocklist.json');
        const rawData = fs.readFileSync(filePath, 'utf-8');
        blocklist = JSON.parse(rawData);
    });

    test('should parse as an object', () => {
        expect(typeof blocklist).toBe('object');
        expect(blocklist).not.toBeNull();
    });

    test('should have expected categories', () => {
        expect(blocklist).toHaveProperty('ads');
        expect(blocklist).toHaveProperty('trackers');
        expect(blocklist).toHaveProperty('malware');
    });

    test('should contain known ad domains', () => {
        expect(blocklist.ads).toContain('doubleclick.net');
        expect(blocklist.ads).toContain('googlesyndication.com');
    });
});
