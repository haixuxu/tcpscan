#!/bin/bash

if [ $# -ne 1 ];then
  echo "Usage: $0 ipsec.txt"
  exit 1
fi

port=22
echo "start scan $port..."
type1="^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]{1,2}$"
type2="^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:blank:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"
validip="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[[:blank:]]+$port[[:blank:]]+Open$"

cat $1|while read line|| [ -n "$line" ];do
  if [[ "$line" =~ $type1 || "$line" =~ $type2 ]];then
  	ipsec=$(printf $line |tr -d '\n')
	# scancmd="./tcpscan tcp $ipsec $port /T512 /Save"
	scancmd="./tcpscan syn $ipsec $port /Save"
	echo "exec $scancmd"
    ret=eval $scancmd
    echo $ret
  else
    echo "line type unknow."
    exit 1
  fi
done

cat "Result.txt" | while read line|| [ -n "$line" ];do
	if [[ "$line" =~ $validip ]];then
		new_str=$(echo $line | cut -d " " -f1);#我处理的方式为以空格分割字符串 取第一个  
		echo $new_str >> targets.txt       #写入到新的文本中 并自动换行  
	fi
done  