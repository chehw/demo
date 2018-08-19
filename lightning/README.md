#lightning-network demo


## Dependencies:
These dependencies are required:

-- json-c : 
	apt-get install libjson-c-dev

-- libsecp256k1:
	git clone git@github.com:bitcoin/bitcoin.git
	cd bitcoin/src/secp256k1
	./autogen.sh
	./configure
	make 
	sudo make install


## TODO:
...
