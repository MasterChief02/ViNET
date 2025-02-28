all:
	aarch64-linux-android-g++ ViNET/Core/EncryptNonBlock.cpp -o core -lnetfilter_queue -lssl -lcrypto
	aarch64-linux-android-g++ ViNET/Core/CoreConstString.cpp -o core_append -lnetfilter_queue -lssl -lcrypto
	aarch64-linux-android-g++ ViNET/Middle/Netcat.cpp -o netcat -lpthread
	aarch64-linux-android-g++ ViNET/Middle/Router.cpp -o router -lpthread
