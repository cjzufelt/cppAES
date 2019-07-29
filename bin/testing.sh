for i in {1..100}
do
echo "128: $i"
./c++aes e 128 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./c++aes d 128 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
done

for i in {1..100}
do
echo "196: $i"
./c++aes e 192 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./c++aes d 192 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
done

for i in {1..100}
do 
echo "256: $i"
./c++aes e 256 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
./c++aes d 256 ~/Desktop/ISRL/Ransomware/AES/encryptFiles
done

cat ~/Desktop/ISRL/Ransomware/AES/encryptFiles/1.txt
cat ~/Desktop/ISRL/Ransomware/AES/encryptFiles/2.txt
cat ~/Desktop/ISRL/Ransomware/AES/encryptFiles/3.txt
