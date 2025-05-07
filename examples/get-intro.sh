#!/bin/sh
#
# Collect a signature from a remote machine's /tmp/sign/sock
# and add it to your certified-config directory.

which certified >/dev/null || {
    echo 'Certified package not installed. use `pip install certified`'
    exit 1
}

if [ $# -lt 1 ]; then
    echo "Usage: $0 [--test] <arguments to ssh> ..."
    echo "Example: $0 name@hpc.company.com"
    echo "Example: $0 -J name@bastion-host.company.com name@hpc.company.com"
    exit 1
fi

echo_only=false
if [ x"$1" = x"--test" ]; then
    shift
    echo_only=true
fi

f=`mktemp sign-XXXXXX.json`
x=`certified get-ident`

ssh $@ curl --unix-socket /tmp/sign/sock -X POST -H 'accept: application/json' http://localhost/sign?cert=$x >$f || {

    echo "Invalid response from server's /tmp/sign/sock. Is the server running?"
    rm $f
    exit 1
}

echo 'Successful signature.'
if [ $echo_only = true ]; then
    cat $f
else
    certified add-intro $f
fi
rm -f $f
