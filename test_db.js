require('./db').query('SELECT * FROM app_settings WHERE setting_key LIKE "%discord%"').then(r => console.log(r[0])).finally(()=>process.exit());
