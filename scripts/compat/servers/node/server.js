const http = require('http')
const fs = require('fs')
const path = require('path')

const port = parseInt(process.argv[2] || '8080', 10)
const testdata = path.join(__dirname, '../../../../testdata')

http.createServer((req, res) => {
    if (req.url === '/hello') {
        res.end('Hello, world')
        return
    }
    const file = path.join(testdata, req.url)
    const stream = fs.createReadStream(file)
    stream.on('error', () => { res.writeHead(404); res.end('not found') })
    stream.on('open', () => {
        res.writeHead(200)
        stream.pipe(res)
    })
}).listen(port, () => console.log(`listening on :${port}`))
