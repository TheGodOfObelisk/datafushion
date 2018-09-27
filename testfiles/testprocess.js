// var child_process = require('child_process')
// py = child_process.spawn('python',['./testprocess.py'])
// py.stdout.on('data', (data) => {
// 	console.log('data ,,,,')
// })

// const {exec}  = require('child_process');
// exec('python testprocess.py', (err, stdout, stderr) => {
// 	if (err) {
// 		console.error(`exec error: ${err}`);
// 		return;
// 	}
// 	console.log(`Number of files ${stdout}`);
// });


const {spawn} = require('child_process');
const child = spawn('python testprocess.py',{
	shell: true
});
// child.stdin.pipe('hello')
child.stdout.pipe(process.stdout);


// const {spawn} = require('child_process');
// child = spawn('python',['testprocess.py']);

// child.stdout.on('data', function(chunk){
// 	let data = chunk.toString();
// 	let message = JSON.parse(data);
// 	console.log(`${message.a} ${message.b}`);
// });

// const { spawn } = require('child_process');
// child = spawn('python',['testprocess.py']);

// child.stdout.setEncoding('utf8');
// 父进程-发
// child.stdin.write(JSON.stringify({
//   type: 'handshake',
//   payload: '你好吖'
// }));

// child.stdin.write('hello');

// child.stdout.on('data', (data) => {
// 	//let data = chunk.toString();
// 	console.log(`${data}`);
// })