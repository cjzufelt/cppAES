for i in {1..100}
do
echo "128: $i"
./cppAES e 128 1024 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES d 128 1024 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES e 128 2048 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES d 128 2048 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES e 128 3072 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES d 128 3072 ~/Desktop/ISRL/Ransomware/AES/encryptFiles

done

for i in {1..100}
do
echo "196: $i"
./cppAES e 192 1024 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES d 192 1024 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES e 192 2048 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES d 192 2048 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES e 192 3072 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES d 192 3072 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
done

for i in {1..100}
do
echo "256: $i"
./cppAES e 256 1024 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES d 256 1024 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES e 256 2048 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES d 256 2048 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES e 256 3072 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./cppAES d 256 3072 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
done

cat ~/Desktop/ISRL/Ransomware/AES/encryptFiles/1.txt
cat ~/Desktop/ISRL/Ransomware/AES/encryptFiles/2.txt
cat ~/Desktop/ISRL/Ransomware/AES/encryptFiles/3.txt
