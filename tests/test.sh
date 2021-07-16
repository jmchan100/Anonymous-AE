# 100 keys, 512 bytes msg, 200 rounds
python -m cProfile speedTest.py nae 100 512 200 > test_runs/nae-100-512-200.txt
python -m cProfile speedTest.py naive 100 512 200 > test_runs/naive-100-512-200.txt
python -m cProfile speedTest.py base 100 512 200 > test_runs/base-100-512-200.txt
python -m cProfile speedTest.py dict 100 512 200 > test_runs/dict-100-512-200.txt

# 500 keys, 512 bytes msg, 200 rounds
python -m cProfile speedTest.py nae 500 512 200 > test_runs/nae-500-512-200.txt
python -m cProfile speedTest.py naive 500 512 200 > test_runs/naive-500-512-200.txt
python -m cProfile speedTest.py base 500 512 200 > test_runs/base-500-512-200.txt
python -m cProfile speedTest.py dict 500 512 200 > test_runs/dict-500-512-200.txt

# 1000 keys, 512 bytes msg, 200 rounds
python -m cProfile speedTest.py nae 1000 512 200 > test_runs/nae-1000-512-200.txt
python -m cProfile speedTest.py naive 1000 512 200 > test_runs/naive-1000-512-200.txt
python -m cProfile speedTest.py base 1000 512 200 > test_runs/base-1000-512-200.txt
python -m cProfile speedTest.py dict 1000 512 200 > test_runs/dict-1000-512-200.txt




# 100 keys, 2048 bytes msg, 200 rounds
python -m cProfile speedTest.py nae 100 2048 200 > test_runs/nae-100-2048-200.txt
python -m cProfile speedTest.py naive 100 2048 200 > test_runs/naive-100-2048-200.txt
python -m cProfile speedTest.py base 100 2048 200 > test_runs/base-100-2048-200.txt
python -m cProfile speedTest.py dict 100 2048 200 > test_runs/dict-100-2048-200.txt

# 250 keys, 2048 bytes msg, 200 rounds
#python -m cProfile speedTest.py nae 250 2048 200 > test_runs/nae-250-2048-200.txt
#python -m cProfile speedTest.py naive 250 2048 200 > test_runs/naive-250-2048-200.txt
#python -m cProfile speedTest.py base 250 2048 200 > test_runs/base-250-2048-200.txt
#python -m cProfile speedTest.py dict 250 2048 200 > test_runs/dict-250-2048-200.txt

# 500 keys, 2048 bytes msg, 200 rounds
python -m cProfile speedTest.py nae 500 2048 200 > test_runs/nae-500-2048-200.txt
python -m cProfile speedTest.py naive 500 2048 200 > test_runs/naive-500-2048-200.txt
python -m cProfile speedTest.py base 500 2048 200 > test_runs/base-500-2048-200.txt
python -m cProfile speedTest.py dict 500 2048 200 > test_runs/dict-500-2048-200.txt

# 1000 keys, 2048 bytes msg, 200 rounds
python -m cProfile speedTest.py nae 1000 2048 200 > test_runs/nae-1000-2048-200.txt
python -m cProfile speedTest.py naive 1000 2048 200 > test_runs/naive-1000-2048-200.txt
python -m cProfile speedTest.py base 1000 2048 200 > test_runs/base-1000-2048-200.txt
python -m cProfile speedTest.py dict 1000 2048 200 > test_runs/dict-1000-2048-200.txt



# 100 keys, 4096 bytes msg, 200 rounds
python -m cProfile speedTest.py nae 100 4096 200 > test_runs/nae-100-4096-200.txt
python -m cProfile speedTest.py naive 100 4096 200 > test_runs/naive-100-4096-200.txt
python -m cProfile speedTest.py base 100 4096 200 > test_runs/base-100-4096-200.txt
python -m cProfile speedTest.py dict 100 4096 200 > test_runs/dict-100-4096-200.txt

# 250 keys, 4096 bytes msg, 200 rounds
#python -m cProfile speedTest.py nae 250 4096 200 > test_runs/nae-250-4096-200.txt
#python -m cProfile speedTest.py naive 250 4096 200 > test_runs/naive-250-4096-200.txt
#python -m cProfile speedTest.py base 250 4096 200 > test_runs/base-250-4096-200.txt
#python -m cProfile speedTest.py dict 250 4096 200 > test_runs/dict-250-4096-200.txt

# 500 keys, 4096 bytes msg, 200 rounds
python -m cProfile speedTest.py nae 500 4096 200 > test_runs/nae-500-4096-200.txt
python -m cProfile speedTest.py naive 500 4096 200 > test_runs/naive-500-4096-200.txt
python -m cProfile speedTest.py base 500 4096 200 > test_runs/base-500-4096-200.txt
python -m cProfile speedTest.py dict 500 4096 200 > test_runs/dict-500-4096-200.txt

# 1000 keys, 4096 bytes msg, 200 rounds
python -m cProfile speedTest.py nae 1000 4096 200 > test_runs/nae-1000-4096-200.txt
python -m cProfile speedTest.py naive 1000 4096 200 > test_runs/naive-1000-4096-200.txt
python -m cProfile speedTest.py base 1000 4096 200 > test_runs/base-1000-4096-200.txt
python -m cProfile speedTest.py dict 1000 4096 200 > test_runs/dict-1000-4096-200.txt


