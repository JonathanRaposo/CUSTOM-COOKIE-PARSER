const mongoose = require('mongoose');



module.exports = async (databaseUri) => {
    try {
        const x = await mongoose.connect(databaseUri);
        console.log(`Connected to Mongo.Database name:${x.connections[0].name}`)
    } catch (err) {
        console.log(`Error connecting to Mongo:${err}`);
    }
}