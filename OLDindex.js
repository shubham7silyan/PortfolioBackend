const mongoose = require('mongoose');

mongoose.connect('mongodb://127.0.0.1:27017/portfolioDB')
    .then(() => {
        console.log('Connected');
    })
    .catch((err) => {
        console.log(err);
    });

const SchemaName = new mongoose.Schema({
    FirstName: String,
    LastName: String,
    Email: String,
    Message: String
},
{
    versionKey: false
});

const http = require('http');
const url = require('url');
const fs = require('fs');

http.createServer(function(req, res) {
    const q = url.parse(req.url, true);

    const data = q.query;
    console.log(data);

    fs.readFile('./portfolio/src/components/contact.jsx', function (err, fileData) {
        if (err) {
            res.writeHead(404, { 'content-Type': 'text/html' });
            return res.end('404 Not Found');

        }
        res.writeHead(200, { 'content-Type': 'text/html' });
        res.write(fileData);
        return res.end();
    });
    const UserModel = mongoose.model('formdata', SchemaName);
    const InsertedData = new UserModel(data);

    InsertedData.save()
        .then(() => console.log('data Inserted successfully'))
        .catch((err) => console.log(err));
}).listen(5050);
