make clean
make static
sudo make install
sudo systemctl daemon-reload
sudo systemctl restart crio
