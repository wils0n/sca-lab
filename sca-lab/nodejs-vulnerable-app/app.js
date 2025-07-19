const express = require('express');
const _ = require('lodash');
const minimist = require('minimist');

const app = express();
const port = 3000;

app.get('/', (req, res) => {
    const data = _.merge({}, req.query);
    res.json({ message: 'Aplicación vulnerable', data: data });
});

app.listen(port, () => {
    console.log(`Aplicación corriendo en puerto ${port}`);
});
