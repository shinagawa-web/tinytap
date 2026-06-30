const http = require('http')
const fs = require('fs')
const path = require('path')

const port = parseInt(process.argv[2] || '8080', 10)
const testdata = path.join(__dirname, '../../../../testdata')

http.createServer((req, res) => {
    const file = path.join(testdata, req.url)
    fs.readFile(file, (err, data) => {
        if (err) { res.writeHead(404); res.end('not found'); return }
        res.writeHead(200, { 'Content-Length': data.length })
        res.end(data)
    })
}).listen(port, () => console.log(`listening on :${port}`))
