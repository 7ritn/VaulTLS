#!/bin/sh
/app/bin/backend > /dev/stdout 2> /dev/stderr &
exec nginx