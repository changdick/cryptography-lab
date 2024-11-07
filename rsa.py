import random
import time
def _miller_rabin_test(d: int, n: int) -> bool:
    """
    使用Miller-Rabin算法测试n是否为素数的单轮测试。
    参数:
        d: n-1的奇数部分
        n: 要测试的数
    返回:
        如果n可能是素数，返回True；否则返回False。
    """
    a = 2 + random.randint(1, n - 4)
    x = quick_pow(a, d, n)

    if x == 1 or x == n - 1:
        return True

    while d != n - 1:
        x = (x * x) % n
        d *= 2

        if x == 1:
            return False
        if x == n - 1:
            return True

    return False


def is_prime(n: int, k: int = 5) -> bool:
    """
    判断一个数n是否为素数，使用k轮Miller-Rabin测试。
    参数:
        n: 要判断的数
        k: 测试的轮数，默认为5轮，轮数越多结果越准确。
    返回:
        如果n是素数，返回True；否则返回False。
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    d = n - 1
    while d % 2 == 0:
        d //= 2

    for _ in range(k):
        if not _miller_rabin_test(d, n):
            return False

    return True


def gen_large_prime() -> int:
    """
    生成一个至少64位的十进制大素数。
    返回:
        一个至少64位的素数。
    """
    # 生成一个随机的64位
    large_prime = random.randint(2**1023, 2**1024 - 1)
    while True:        
        if is_prime(large_prime):
            return large_prime
        large_prime += 1


# 扩展欧几里得算法
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    else:
        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y
    
# 使用扩展欧几里得算法计算模逆
def mod_inverse(e, phi_n):
    """
    计算RSA算法中的模逆。  
    参数:
        e: RSA算法中的公钥指数
        phi_n: 欧拉函数φ(n)，即(p-1)*(q-1)，其中p和q是两个大素数
    返回:
        d: e模phi_n的乘法逆元，即满足(e * d) % phi_n == 1的整数d
    异常:
        ValueError: 如果e与phi_n不是互质的，则模逆不存在，抛出此异常
    """
    gcd, x, y = extended_gcd(e, phi_n)
    if gcd != 1:
        raise ValueError("模逆不存在，因为e与phi(n)不是互质的")
    else:
        return x % phi_n  # 保证结果为正整数
    

def quick_pow(m,e,n): # 快速取幂模
    ans = 1
    while e:
        if e & 1:
            ans = (ans * m) % n
        m = m * m % n
        e >>= 1
    return ans

def key_gen():
    """
    生成RSA密钥对。

    生成rsa算法中需要用到的各个数字并返回，包括：
    1 该函数调用gen_large_prime生成两个大素数p和q，
    2 计算它们的乘积n和欧拉函数phi_n，
    3 选择一个常用的公钥指数e,直接使用65537，并计算e模phi_n的乘法逆元d。 
    
    返回:
        p: 大素数
        q: 大素数
        n: 模数，等于p和q的乘积
        e: 公钥指数
        d: 私钥指数，使得(e * d) % phi_n == 1
    """
    p = gen_large_prime()
    q = gen_large_prime()
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi_n)
    return p, q, n, phi_n, e, d

def rsa_encrypt(plaintext_list, e, n):
    """
    RSA加密函数
    
    参数:
        plaintext_list: 明文列表，每个元素是一个整数，表示要加密的明文
        e: 公钥指数
        n: 模数，等于两个大素数p和q的乘积
    
    返回:
        ciphertext_list: 密文列表，每个元素是一个整数，表示加密后的密文
    """
    ciphertext_list = []
    for m in plaintext_list:
        c = quick_pow(m, e, n)  # 使用快速幂模加密
        ciphertext_list.append(c)
    return ciphertext_list

def rsa_decrypt(ciphertext_list, d, n):
    """
    RSA解密函数
    
    参数:
        ciphertext_list: 密文列表，每个元素是一个整数，表示要解密的密文
        d: 私钥指数
        n: 模数，等于两个大素数p和q的乘积
    
    返回:
        plaintext_list: 明文列表，每个元素是一个整数，表示解密后的明文
    """
    plaintext_list = []
    for c in ciphertext_list:
        m = quick_pow(c, d, n)  # 使用快速幂模解密
        plaintext_list.append(m)
    return plaintext_list


def read_file_to_int_list(file_path):
    """
    读取文本文件并将字符转换为数字列表,直接使用ascii值
    转换直接把每个字符分成一组，直接转成某个数字
    """
    int_list = []

    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()  # 读取文件内容

    for char in content:
        int_list.append(ord(char))  # 将字符转换为ASCII码并加入到数字列表
    
    return int_list

def int_list_to_string(int_list):
    """
    将整型数组转换为字符串
    """
    char_list = [chr(number) for number in int_list]
    return ''.join(char_list)



def file2int(file_path):
    """
    读取文本文件并将字符转换为数字列表,先转换成100以内的值映射补成4位
    两两分组凑成4位数字，并返回原始字符串长度用于删除自动补充的空格
    输入：明文文件路径
    输出：四位整数列表，原始字符个数
    """
    int_list = []

    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()  # 读取文件内容

    # 可显示字符的起始和结束ASCII码
    start_ascii = 32
    end_ascii = 126

    # 将每个可显示字符转换为两位十进制数字
    for char in content:
        if start_ascii <= ord(char) <= end_ascii:
            # 计算两位十进制数字
            two_digit_num = ord(char) - start_ascii
            int_list.append(f"{two_digit_num:02d}")  # 保证是两位数字

    original_len = len(int_list)

    # 如果字符个数是奇数，补充一个空格字符（ASCII 32 -> 00）
    if len(int_list) % 2 != 0:
        int_list.append("00")

    # 将数字两两拼接成四位数字
    four_digit_list = []
    for i in range(0, len(int_list), 2):
        four_digit = int_list[i] + int_list[i + 1]
        four_digit_list.append(int(four_digit))  # 转换为整数

    return four_digit_list , original_len

def int2string(int_list):
    """将四位整型数组转换为字符串"""
    char_list = []

    for number in int_list:
        # 将四位数字分解为两个两位数字
        first_two_digits = number // 100  # 前两位
        second_two_digits = number % 100   # 后两位

        # 将两位数字映射回字符（加上32以得到ASCII值）
        if 0 <= first_two_digits <= 94:
            char_list.append(chr(first_two_digits + 32))  # 对应的字符
        if 0 <= second_two_digits <= 94:
            char_list.append(chr(second_two_digits + 32))  # 对应的字符

    # 拼接成字符串
    return ''.join(char_list)


if __name__ == '__main__':
      # 1. 生成RSA密钥对
    p, q, n, phi_n, e, d = key_gen()
    print(f"生成的素数 p: {p}")
    print(f"生成的素数 q: {q}")
    print(f"模数 n: {n}")
    print(f"欧拉函数 φ(n): {phi_n}")
    print(f"公钥指数 e: {e}")
    print(f"私钥指数 d: {d}")

    # 2. 从文件读取明文并转换为整型数组
    # 注释掉的是使用第一种字符转换方法，直接每个字符分组用ascii码
    # plaintext_list = read_file_to_int_list('lab2-Plaintext.txt')
    # print(f"明文整型数组: {plaintext_list}")

    plaintext_list, original_len = file2int('lab2-Plaintext.txt')
    print("明文整型数组: ", [f"{num:04d}" for num in plaintext_list])
    
    # 3. RSA加密
    start_time = time.time()

    ciphertext_list = rsa_encrypt(plaintext_list, e, n)
    encrypt_time = time.time() - start_time
    # print(f"加密后的密文: {ciphertext_list}")
    # 将密文写入文件
    with open("encrypted-text.txt", "w") as f:
        for c in ciphertext_list:
            f.write(f"{c}\n")
    print("该密文已经被同时写入到文件encrypted-text.txt中")
    print(f"加密时间: {encrypt_time:.6f}秒")

    # 4. RSA解密
    # decrypted_plaintext_list = rsa_decrypt(ciphertext_list, d, n)
    # print(f"解密后的明文整型数组: {decrypted_plaintext_list}")

    with open("encrypted-text.txt", "r") as f:
        read_ciphertext_list = [int(line.strip()) for line in f.readlines()]
    print("已读取加密文件encrypted-text.txt中的密文，开始解密")
    start_time = time.time()
    decrypted_plaintext_list = rsa_decrypt(read_ciphertext_list, d, n)
    decrypt_time = time.time() - start_time
    print(f"解密时间: {decrypt_time:.6f}秒")
    print(f"解密后的明文整型数组: {decrypted_plaintext_list}")

    # 5. 将解密后的整型数组转换为字符串
    # decrypted_string = int_list_to_string(decrypted_plaintext_list)
    # print(f"解密得到的字符串: {decrypted_string}")

    decrypted_string = int2string(decrypted_plaintext_list)
    if original_len % 2 != 0:
        decrypted_string = decrypted_string[:-1]


    # 6. 将解密结果写入文件 sb.txt
    write2file_name = 'sb.txt'
    with open(write2file_name, 'w', encoding='utf-8') as output_file:
        output_file.write(decrypted_string)

    print(f"解密结果已写入{write2file_name}文件。")