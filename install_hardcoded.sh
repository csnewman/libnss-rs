cd target/release
cp libnss_hardcoded.so libnss_hardcoded.so.2
sudo install -m 0644 libnss_hardcoded.so.2 /lib
sudo /sbin/ldconfig -n /lib /usr/lib