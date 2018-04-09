#import <Foundation/Foundation.h>
#import "RSADeterministic.h"
#import "JKBigInteger.h"
#import "Pbkdf2Rng.h"
#import "X509Der.h"
#import <Security/Security.h>

JKBigInteger *ZERO;
JKBigInteger *ONE;

@interface GeneratorState : NSObject {
    @public JKBigInteger *d;
    @public JKBigInteger *n;
    @public JKBigInteger *e;
    @public JKBigInteger *p;
    @public JKBigInteger *q;
    @public JKBigInteger *min_p;
    @public JKBigInteger *min_q;
    @public int size_p;
    @public int size_q;
    @public JKBigInteger *min_distance;
}
@property(assign) JKBigInteger *_d;
@property(assign) JKBigInteger *_n;
@property(assign) JKBigInteger *_e;
@property(assign) JKBigInteger *_p;
@property(assign) JKBigInteger *_q;
@property(assign) JKBigInteger *_min_p;
@property(assign) JKBigInteger *_min_q;
@property(assign) int _size_p;
@property(assign) int _size_q;
@property(assign) JKBigInteger *_min_distance;

-(instancetype)init:(int)bits eInt:(unsigned long)eInt;
-(NSDictionary *)toKeyPair;
@end
@interface RsaHelper : NSObject
+(int)getNumMillerRabinTests:(int)bits;
+(JKBigInteger*)generateProbablePrime:(Pbkdf2Rng*)rng state:(GeneratorState*)state;
@end

@implementation GeneratorState : NSObject

-(instancetype)init:(int)bits eInt:(unsigned long)eInt {
    self = [super init];
    
    d = [[JKBigInteger alloc] initWithUnsignedLong:1];
    n = [[JKBigInteger alloc] initWithUnsignedLong:1];
    e = [[JKBigInteger alloc] initWithUnsignedLong:eInt];
    p = [[JKBigInteger alloc] initWithUnsignedLong:0];
    q = [[JKBigInteger alloc] initWithUnsignedLong:0];
    
    size_q = bits / 2;
    size_p = bits - size_q;
    
    min_q = [[ONE shiftLeft:(2*size_q-1)] sqrt];
    min_p = [[ONE shiftLeft:(2*size_p-1)] sqrt];
    min_distance = [ONE shiftLeft:(bits / 2 - 100)];
    return self;
}
-(NSDictionary*)toKeyPair {
    JKBigInteger *version = [[JKBigInteger alloc] initWithUnsignedLong:0];
    JKBigInteger *expP = [d remainder:[p subtract:ONE]];
    JKBigInteger *expQ = [d remainder:[q subtract:ONE]];
    JKBigInteger *coefficient = [q modInverse:p];
    NSArray *privateKeyArr = [NSArray arrayWithObjects:version,n,e,d,p,q,expP,expQ,coefficient,nil];
    NSArray *publicKeyArr = [NSArray arrayWithObjects:n,e,nil];
    
    NSString *privateKeyStr = [X509Der derEncodeRsaKey:privateKeyArr public:false];
    NSString *publicKeyStr = [X509Der derEncodeRsaKey:publicKeyArr public:true];
    return @{@"public" : publicKeyStr, @"private" : privateKeyStr};
}
@end
Pbkdf2Rng *tmpRng = NULL;
@implementation RsaHelper : NSObject

+(int)getNumMillerRabinTests:(int)bits {
    if (bits <= 100) return 27;
    if (bits <= 150) return 18;
    if (bits <= 200) return 15;
    if (bits <= 250) return 12;
    if (bits <= 300) return 9;
    if (bits <= 350) return 8;
    if (bits <= 400) return 7;
    if (bits <= 500) return 6;
    if (bits <= 600) return 5;
    if (bits <= 800) return 4;
    if (bits <= 1250) return 3;
    return 2;
}
+(bool)primeFilter:(JKBigInteger*)candidate state:(GeneratorState*)state {
    JKBigInteger *minus_one = [candidate subtract:ONE];
    JKBigInteger *min = state->min_q;
    bool enoughDistance = true;
    
    if (state->p != NULL) {
        min = state->min_p;
        enoughDistance = [[[candidate subtract:state->p] abs] compare:state->min_distance] > 0;
    }
    JKBigInteger *gcd = [minus_one gcd:state->e];
    assert(gcd != NULL);
    return ([candidate compare:min] > 0) && ([gcd compare:ONE] == 0) && enoughDistance;
}
+(JKBigInteger*) getRandom:(Pbkdf2Rng*)rng bits:(int)bits {
    uint8_t *bytes = [rng nextBytes:((bits+7)/8)];
    NSData *data = [NSData dataWithBytes:bytes length:((bits+7)/8)];
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:data.length*2];
    const uint8_t *buf = data.bytes;
    for (int i=0; i<data.length; i++) {
        [sbuf appendFormat:@"%02x", (unsigned int) buf[i]];
    }
    return [[JKBigInteger alloc] initWithString:sbuf andRadix:16];
}
+(JKBigInteger*) getRandom:(int)bits {
    if (tmpRng == NULL) {
        tmpRng = [[Pbkdf2Rng alloc] init];
    }
    return [RsaHelper getRandom:tmpRng bits:bits];
}
+(bool)millerRabin:(JKBigInteger*)candidate certainty:(int)certainty {
    JKBigInteger* n1 = [candidate subtract:ONE];
    int k = [candidate getLowestSetBit];
    if (k!=0) {
        return false;
    }
    JKBigInteger* r = [n1 shiftRight:k];
    for (int i=0; i<certainty; i++) {
        JKBigInteger *a;
        do {
            a = [RsaHelper getRandom:[candidate getBitLength]];
        } while ([a compare:ONE] <= 0 || [a compare:n1] >= 0);
        JKBigInteger *y = [a pow:r andMod:candidate];
        if ([y compare:ONE] != 0 && [y compare:n1] != 0) {
            for (int j=1; j<k && [y compare:n1] !=0; j++) {
                y = [y pow:[ONE shiftLeft:1] andMod:candidate];
                if ([y compare:ONE] == 0) {
                    return false;
                }
            }
            if ([y compare:n1] != 0) {
                return false;
            }
        }
    }
    return true;
}
+(bool)isProbablePrime:(JKBigInteger*)candidate certainty:(int)certainty {
    return [RsaHelper millerRabin:candidate certainty:certainty];
}
+(JKBigInteger*)generateProbablePrime:(Pbkdf2Rng *)rng state:(GeneratorState *)state {
    while (true) {
        int bits = (state->p == NULL) ? state->size_p : state->size_q;
        JKBigInteger *candidate = [RsaHelper getRandom:rng bits:bits];
        candidate = [candidate bitwiseOr:ONE];
        candidate = [candidate bitwiseOr:[ONE shiftLeft:bits-1]];
        if ([RsaHelper primeFilter:candidate state:state] &&
            [RsaHelper isProbablePrime:candidate certainty:[RsaHelper getNumMillerRabinTests:bits]]) {
            return candidate;
        }
    }
}
@end

@implementation RSADeterministic : NSObject
+(NSDictionary*)generateDeterministic:(int)bits eInt:(unsigned long)eInt seed:(NSString *)seed {
    ZERO = [[JKBigInteger alloc] initWithUnsignedLong:0];
    ONE = [[JKBigInteger alloc] initWithUnsignedLong:1];
    
    GeneratorState *state = [[GeneratorState alloc] init:bits eInt:eInt];
    Pbkdf2Rng *rng = [[Pbkdf2Rng alloc] initWithSeed:seed andNumBits:bits];
    
    
    while ([state->n getBitLength] != bits && [state->d compare:[ONE shiftLeft:(bits/2)]] <= 0) {
        state->p = NULL;
        state->q = NULL;
        
        state->p = [RsaHelper generateProbablePrime:rng state:state];
        state->q = [RsaHelper generateProbablePrime:rng state:state];
        
        state->n = [state->p multiply:state->q];
        JKBigInteger *lcm = [[state->p subtract:ONE] lcm:[state->q subtract:ONE]];
        state->d = [state->e modInverse:lcm];
    }
    
    if ([state->p compare:state->q] > 0) {
        JKBigInteger *tmp = state->p;
        state->p = state->q;
        state->q = tmp;
    }
    
    return [state toKeyPair];
}
@end
