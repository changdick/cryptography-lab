from hashlib import sha256
import random


def quick_pow(m,e,n): # 快速取幂模
    """
    计算 m^e mod n 的值。
    """
    ans = 1
    while e:
        if e & 1:
            ans = (ans * m) % n
        m = m * m % n
        e >>= 1
    return ans

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
    生成一个至少1024位的十进制大素数。
    如果素数是安全素数，即p=2q+1，其中p和q都是素数，那么这个p找到g更容易

    返回:
        一个至少1024位的安全素数。
    """
    # 生成一个随机的64位
    while True:   
        large_prime = random.randint(2**63, 2**64 - 1)
            
        if is_prime(large_prime):
            q = (large_prime - 1) // 2
            if is_prime(q):
                return large_prime

def find_generator(p: int) -> int:
    """
    找到一个p的原根。
    因为p是安全素数，求出q=(p-1)/2是素数，p的原根g满足g^2 mod p != 1, g^q mod p != 1，可以用这两个判断一个数是否是原根
    参数:
        p: 素数，是用gen_large_prime生成的安全素数。
    返回:
        p的一个原根。
    """
    q = ((p - 1) // 2)
    for g in range(2 , p):
        # 若同时满足下面两个条件，则g是p的原根
        if quick_pow(g, 2, p) != 1 and quick_pow(g, q, p) != 1:
            return g
    return None


def gen_key():
    """
    生成公钥和私钥。自动生成大素数p和原根g，私钥x，公钥y。
    返回:
        (p,g,y,x) 依次是大素数p，原根g，公钥y，私钥x
    """       
    p = gen_large_prime()      # 生成大素数p，且p是安全素数
    g = find_generator(p)      # 生成p的原根g
    x = random.randint(2, p-2) # 生成私钥x ， x满足 1 < x < p-1
    y = quick_pow(g, x, p)     # 生成公钥y
    return p, g, y, x          # 返回公钥和私钥
    

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
    
def signmsg(m , p , g , x):
    # 首先生成k, 1 < k < p-1,要求k与p-1互质，并求出k mod p-1 的逆元.可以用扩展欧几里得算法求逆元
    
    while True:
        k = random.randint(2, p-2)  # 生成随机数k < p-1
        gcd , k_inv , _ = extended_gcd(k , p-1) # 直接用扩展欧几里得算法
        if gcd == 1: # 当gcd == 1时，k与p-1互质，此时k_inv同时为k的逆元，可以结束循环
            break
    print("本次签名使用的k: ", k)    
    # 计算H(m), H用SHA256
    H_m = sha256(m.encode()).hexdigest()
    H_int = int(H_m, 16) # 将H转换为整数
    # 计算r
    r = quick_pow(g, k, p) # r = g^k mod p
    # 计算s
    s = k_inv * (H_int - x * r) % (p - 1) 
    # 返回签名
    return r , s

def verify(m , r, s , p , g , y):
    # 计算H(m), H用SHA256
    H_m = sha256(m.encode()).hexdigest()
    H_int = int(H_m, 16) # 将H转换为整数
    yrrs = quick_pow(y, r, p) * quick_pow(r, s, p) % p   # 等式左边
    gH = quick_pow(g, H_int, p) # 等式右边
    if yrrs == gH:
        return True
    return False

if __name__ == "__main__":
    # 定义消息
    m = '220110430'
    m_modified = '220110431'
    # 生成密钥对
    print("------1 生成密钥------")
    p, g, y, x = gen_key()
    print("p: ", p)
    print("g: ", g) 
    print("y: ", y)
    print("x: ", x)
    # 签名
    print("------2 第一次签名------")
    print("消息: ", m)
    r1, s1 = signmsg(m, p, g, x)

    print("第一次 r: ", r1)
    print("第一次 s: ", s1)

    # 第二次签名
    print("------3 第二次签名------")
    r2, s2 = signmsg(m, p, g, x)
    print("第二次 r: ", r2)
    print("第二次 s: ", s2)

    # 验证
    print("------4 验证第一次签名结果------")
    print("要验证的消息: ", m_modified)
    if verify(m_modified, r1, s1, p, g, y):
        print("验证成功")
    else:
        print("验证失败")

    # 验证
    print("------5 验证第二次签名结果------")
    if verify(m_modified, r2, s2, p, g, y):
        print("验证成功")
    else:
        print("验证失败")
