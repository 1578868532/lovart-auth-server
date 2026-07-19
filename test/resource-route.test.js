const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

delete process.env.DATABASE_URL;
delete process.env.POSTGRES_URL;
delete process.env.CHANNEL_DATABASE_URL;
delete process.env.CHANNEL_POSTGRES_URL;

const { app } = require('../server');

async function withServer(run) {
    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
        const address = server.address();
        return await run(`http://127.0.0.1:${address.port}`);
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
}

test('Render service exposes auth and resource health routes together', async () => {
    await withServer(async baseUrl => {
        const authResponse = await fetch(`${baseUrl}/api/health`);
        assert.equal(authResponse.status, 200);
        const auth = await authResponse.json();
        assert.equal(auth.success, true);
        assert.equal(auth.resourceApiMounted, true);

        const resourceResponse = await fetch(`${baseUrl}/api?action=health`);
        assert.equal(resourceResponse.status, 200);
        const resource = await resourceResponse.json();
        assert.equal(resource.success, true);
        assert.equal(resource.service, 'lovart-card-api');
    });
});
