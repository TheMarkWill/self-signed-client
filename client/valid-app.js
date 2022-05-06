const axios = require('axios');
const agent = require('./agent');

const serverUrl = 'https://localhost:4433/authenticate';
let opts = { httpsAgent: agent('super_mark') };

axios.get(serverUrl, opts)
	.then((res) => {
		console.log(res.data);
	})
	.catch((err) => {
		console.error(err.response.data);
	});
