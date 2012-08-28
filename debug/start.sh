#!/bin/bash
dir=$(dirname "$0")
port=9999
conf=$dir/debug-bitlbee.conf
bin=$dir/../bitlbee
storage=mysql

echo Starting bitlbee ....
echo Binary $bin
echo Listenning on port $port
echo Using $storage storage engine
echo Configuration file $conf
echo From $dir

echo $bin -s $storage -Fn -p $port -c "$conf"
$bin -s $storage -Fn -p $port -c "$conf"
if [ !$! ]; then
    echo tool executed successfully
else
    echo something wrong
    echo $!
fi

