#! bin/sh

# while loop
i=1
while [ $i -le 50 ]
    do
    # sleep 30ms
    sleep 0.03
    # curl in a new thread
    curl -s -o /dev/null -w "%{http_code}" http://localhost:10000/ &
    i=$((i+1))
done
