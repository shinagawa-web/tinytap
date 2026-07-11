import path from 'path'

const port = parseInt(process.argv[2] || '8080', 10)
const testdata = path.join(import.meta.dir, '../../../../testdata')

Bun.serve({
    port,
    async fetch(req) {
        const url = new URL(req.url)
        if (url.pathname === '/hello') {
            return new Response('Hello, world')
        }
        // req.url is untrusted; normalize collapses any ".." before it
        // reaches path.join, so the result can never escape testdata (a
        // bare path.join(testdata, url.pathname) would otherwise allow
        // traversal).
        const file = Bun.file(path.join(testdata, path.normalize(url.pathname)))
        if (!(await file.exists())) {
            return new Response('not found', { status: 404 })
        }
        return new Response(file)
    },
})

console.log(`listening on :${port}`)
