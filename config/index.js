const path = require('path');
const express = require('express');
const logger = require('morgan');


module.exports = (app) => {
    app.use(express.urlencoded({ extended: false }))
    app.use(logger('dev'));
    app.set('views', path.join(__dirname, '..', 'views'));
    app.set('view engine', 'hbs');
    app.use(express.static(path.join(__dirname, '..', 'static-files')));
}