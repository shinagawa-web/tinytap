const http = require('http')
const fs = require('fs')
const path = require('path')

const port = parseInt(process.argv[2] || '8080', 10)
const testdata = path.join(__dirname, '../../../../testdata')

const CONTENT_TYPES = { '.png': 'image/png' }

http.createServer((req, res) => {
    if (req.url === '/hello') {
        res.end('Hello, world')
        return
    }
    const file = path.join(testdata, req.url)
    const contentType = CONTENT_TYPES[path.extname(file)] || 'text/plain'
    const stream = fs.createReadStream(file)
    stream.on('error', () => { res.writeHead(404); res.end('not found') })
    stream.on('open', () => {
        // No explicit Content-Length: this is the natural result of
        // createReadStream(...).pipe(res) per #43's setup, which makes
        // Node fall back to chunked Transfer-Encoding.
        res.writeHead(200, { 'Content-Type': contentType })
        stream.pipe(res)
    })
}).listen(port, () => console.log(`listening on :${port}`))
