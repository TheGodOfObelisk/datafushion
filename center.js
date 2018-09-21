var WebSocket = require('ws')
var socket = new WebSocket('ws://localhost:3368');
// socket.onmessage = function(result,nTime){
// alert("从服务端收到的数据:");
// alert("最近一次发送数据到现在接收一共使用时间:" + nTime);
// console.log(result);
// }

//var data = {key:'value',hello:'world'};
var count = 0
socket.on('message',function(data){
    console.log("从服务器接收到的信息：",data)
    // socket.send('我很好 你呢？')
    count++
    if(count == 1)
    	socket.send('start_detect_live_host')//signal
    if(count == 2)
    	socket.send('end_detect_live_host')

})
socket.on('open',function(){
	console.log('new connecting..');
	//socket.send(JSON.stringify(data));
    socket.send('init_agents')
    // socket.send('start_detect_live_host')//signal
    // socket.send('123')
})
socket.on('error', function(error){
	console.log(`error: ${error}`)
})
socket.on('close',function(){
	 console.log('connection close!')
})

