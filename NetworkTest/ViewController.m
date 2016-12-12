//
//  ViewController.m
//  NetworkTest
//
//  Created by apple on 16/9/21.
//  Copyright © 2016年 anran. All rights reserved.
//

#import "ViewController.h"
#import "HttpManager.h"
@interface ViewController ()<NSURLSessionDataDelegate,UIWebViewDelegate>{
    NSURLRequest*_originRequest;
    
    NSURLConnection*_urlConnection;
    
    BOOL _authenticated;
}

@property(nonatomic,copy)NSString *etag;
@property(nonatomic,strong)  UIWebView *webView;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    UIButton *btn = [[UIButton alloc]initWithFrame:CGRectMake(100, 100, 200, 100)];
    [btn setTitle:@"AFNetworking" forState:UIControlStateNormal];
    [btn setBackgroundColor:[UIColor redColor]];
    [btn addTarget:self action:@selector(btnClicked) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];
    
    UIButton *btn1 = [[UIButton alloc]initWithFrame:CGRectMake(100, 300, 200, 100)];
    [btn1 setTitle:@"webview" forState:UIControlStateNormal];
    [btn1 setBackgroundColor:[UIColor redColor]];
    [btn1 addTarget:self action:@selector(webClick) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn1];
    
}

- (void)btnClicked {
    NSString *urlString = @"https://192.168.1.115:84/miracle/changelogin.action";
    NSMutableDictionary *user = [NSMutableDictionary dictionary];
    
    [user setObject:@"18325752695" forKey:@"phone"];
    
    [user setObject:@"123456" forKey:@"psw"];
    HttpManager *httpManager = [HttpManager shareHttpManager];
    [httpManager post:urlString withParameters:user success:^(NSURLSessionDataTask *task, id responseObject) {
        NSLog(@"success");
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        NSLog(@"failure");
    }];
}

- (void)webClick {
    _webView = [[UIWebView alloc]initWithFrame:CGRectMake(0, 400, 300, 100)];
    [self.view  addSubview:_webView];
    _webView.delegate = self;
    _originRequest = [NSURLRequest requestWithURL:[NSURL  URLWithString:@"https://www.miracleqiji.com:443/miracle/register_explain.jsp"]];
    _urlConnection= [[NSURLConnection alloc]initWithRequest:_originRequest delegate:self];
    [_urlConnection start];
}
- (BOOL)webView:(UIWebView*)webView shouldStartLoadWithRequest:(NSURLRequest*)request navigationType:(UIWebViewNavigationType)navigationType

{
    
    NSLog(@"Did start loading: %@ auth:%d", [[request URL]absoluteString],_authenticated);
    
    if(!_authenticated) {
        [_webView stopLoading];
        _authenticated=NO;
        _urlConnection= [[NSURLConnection alloc]initWithRequest:_originRequest delegate:self];
        
        [_urlConnection start];
        [_webView stopLoading];
        return NO;
        
    }
    
    return YES;
    
}

-(void)webView:(UIWebView*)webView didFailLoadWithError:(NSError*)error{
    
    // 102 == WebKitErrorFrameLoadInterruptedByPolicyChange
    
    NSLog(@"***********error:%@,errorcode=%ld,errormessage:%@",error.domain,(long)error.code,error.description);
    
    if(!([error.domain isEqualToString:@"WebKitErrorDomain"] && error.code==102)) {
        
        //当请求出错了会做什么事情
        
    }
    
}
- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if(challenge.proposedCredential && !challenge.error)
    {
        [challenge.sender useCredential:challenge.proposedCredential forAuthenticationChallenge:challenge];
        
        return;
    }
    NSString *strAuthenticationMethod = challenge.protectionSpace.authenticationMethod;
    NSLog(@"authentication method: %@", strAuthenticationMethod);
    
    NSURLCredential *credential = nil;
    if([strAuthenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate])
    {
        // gets a certificate from local resources
        /**
         *  服务器给的验证证书
         */
        NSString *thePath = [[NSBundle mainBundle] pathForResource:@"mykey1" ofType:@"p12"];
        NSData *PKCS12Data = [[NSData alloc] initWithContentsOfFile:thePath];
        CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
        
        SecIdentityRef identity;
        // extract the ideneity from the certificate
        [self extractIdentity :inPKCS12Data :&identity];
        
        SecCertificateRef certificate = NULL;
        SecIdentityCopyCertificate (identity, &certificate);
        
        const void *certs[] = {certificate};
        CFArrayRef certArray = CFArrayCreate(kCFAllocatorDefault, certs, 1, NULL);
        // create a credential from the certificate and ideneity, then reply to the challenge with the credential
        credential = [NSURLCredential credentialWithIdentity:identity certificates:(__bridge NSArray*)certArray persistence:NSURLCredentialPersistencePermanent];
//        [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
    }
    else if([strAuthenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        int trustCertificateCount = (int)SecTrustGetCertificateCount(challenge.protectionSpace.serverTrust);
        NSMutableArray *trustCertificates = [[NSMutableArray alloc] initWithCapacity:trustCertificateCount];
        for(int i = 0; i < trustCertificateCount; i ++)
        {
            SecCertificateRef trustCertificate =  SecTrustGetCertificateAtIndex(challenge.protectionSpace.serverTrust, i);
            [trustCertificates addObject:(__bridge id) trustCertificate];
        }
        
        SecPolicyRef policyRef = NULL;
        policyRef = SecPolicyCreateSSL(YES, (__bridge CFStringRef) challenge.protectionSpace.host);
        
        SecTrustRef trustRef = NULL;
        if(policyRef)
        {
            SecTrustCreateWithCertificates((__bridge CFArrayRef) trustCertificates, policyRef, &trustRef);
            CFRelease(policyRef);
        }
        
        if(trustRef)
        {
            //          SecTrustSetAnchorCertificates(trustRef, (__bridge CFArrayRef) [NSArray array]);
            //          SecTrustSetAnchorCertificatesOnly(trustRef, NO);
            
            SecTrustResultType result;
            OSStatus trustEvalStatus = SecTrustEvaluate(trustRef, &result);
            if(trustEvalStatus == errSecSuccess)
            {
                // just temporary attempt to make it working.
                // i hope, there is no such problem, when we have final working version of certificates.
                if(result == kSecTrustResultRecoverableTrustFailure)
                {
                    CFDataRef errDataRef = SecTrustCopyExceptions(trustRef);
                    SecTrustSetExceptions(trustRef, errDataRef);
                    
                    SecTrustEvaluate(trustRef, &result);
                }
                
                if(result == kSecTrustResultProceed || result == kSecTrustResultUnspecified)
                    credential = [NSURLCredential credentialForTrust:trustRef];
            }
            
            CFRelease(trustRef);
        }
    }
    else
    {
        [challenge.sender cancelAuthenticationChallenge:challenge];
    }
    
    if(credential)
        [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
    else
        [challenge.sender cancelAuthenticationChallenge:challenge];
    
    
    
}

- (OSStatus)extractIdentity:(CFDataRef)inP12Data :(SecIdentityRef*)identity {
    OSStatus securityError = errSecSuccess;
    /**
     *  p12文件的验证密钥
     *
     *  @param "csykum812" 你的p12文件密钥
     *
     *  @return securityError
     */
    CFStringRef password = CFSTR("csykum812");
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12Data, options, &items);
    
    if (securityError == 0) {
        CFDictionaryRef ident = CFArrayGetValueAtIndex(items,0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(ident, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
        
    }
    
    if (options) {
        CFRelease(options);
    }
    
    return securityError;
}
- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    
    /*
     
     //直接验证服务器是否被认证（serverTrust），这种方式直接忽略证书验证，信任该connect
     SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
     return [[challenge sender] useCredential: [NSURLCredential credentialForTrust: serverTrust]
     forAuthenticationChallenge: challenge];
     
     */
    
    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString: NSURLAuthenticationMethodServerTrust]) {
        do
        {
            SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
            NSCAssert(serverTrust != nil, @"serverTrust is nil");
            if(nil == serverTrust)
                break; /* failed */
            /**
             *  导入多张CA证书（Certification Authority，支持SSL证书以及自签名的CA），请替换掉你的证书名称
             */
            NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"tomcat1(1)" ofType:@"cer"];//自签名证书
            NSData* caCert = [NSData dataWithContentsOfFile:cerPath];
            
            NSCAssert(caCert != nil, @"caCert is nil");
            if(nil == caCert)
                break; /* failed */
            
            SecCertificateRef caRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)caCert);
            NSCAssert(caRef != nil, @"caRef is nil");
            if(nil == caRef)
                break; /* failed */
            
            
            NSArray *caArray = @[(__bridge id)(caRef)];
            
            NSCAssert(caArray != nil, @"caArray is nil");
            if(nil == caArray)
                break; /* failed */
            
            OSStatus status = SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)caArray);
            NSCAssert(errSecSuccess == status, @"SecTrustSetAnchorCertificates failed");
            if(!(errSecSuccess == status))
                break; /* failed */
            
            SecTrustResultType result = -1;
            status = SecTrustEvaluate(serverTrust, &result);
            if(!(errSecSuccess == status))
                break; /* failed */
            NSLog(@"stutas:%d",(int)status);
            NSLog(@"Result: %d", result);
            
            BOOL allowConnect = (result == kSecTrustResultUnspecified) || (result == kSecTrustResultProceed);
            if (allowConnect) {
                NSLog(@"success");
            }else {
                NSLog(@"error");
            }
            /* https://developer.apple.com/library/ios/technotes/tn2232/_index.html */
            /* https://developer.apple.com/library/mac/qa/qa1360/_index.html */
            /* kSecTrustResultUnspecified and kSecTrustResultProceed are success */
            if(! allowConnect)
            {
                break; /* failed */
            }
            
#if 0
            /* Treat kSecTrustResultConfirm and kSecTrustResultRecoverableTrustFailure as success */
            /*   since the user will likely tap-through to see the dancing bunnies */
            if(result == kSecTrustResultDeny || result == kSecTrustResultFatalTrustFailure || result == kSecTrustResultOtherError)
                break; /* failed to trust cert (good in this case) */
#endif
            
            // The only good exit point
            NSLog(@"信任该证书");
            return [[challenge sender] useCredential: [NSURLCredential credentialForTrust: serverTrust]
                          forAuthenticationChallenge: challenge];
            
        }
        while(0);
    }
    
    // Bad dog
    return [[challenge sender] cancelAuthenticationChallenge: challenge];
    
}

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    
    return [protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust];
}

#pragma mark -- connect的异步代理方法
-(void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    
    NSLog(@"请求被响应");
    _authenticated = YES;
//    //webview 重新加载请求。
//    [_webView loadRequest:_originRequest];
//    [connection cancel];
}

-(void)connection:(NSURLConnection *)connection didReceiveData:(nonnull NSData *)data {
    NSLog(@"开始返回数据片段");
    
}

-(void)connectionDidFinishLoading:(NSURLConnection *)connection {
    NSLog(@"链接完成");
    //可以在此解析数据
    //webview 重新加载请求。
    [_webView loadRequest:_originRequest];
    [connection cancel];
//    NSString *receiveInfo = [NSJSONSerialization JSONObjectWithData:self.mData options:NSJSONReadingAllowFragments error:nil];
//    NSLog(@"received data:\n%@",self.mData);
//    NSLog(@"received info:\n%@",receiveInfo);
}

//链接出错
-(void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    
    NSLog(@"error - %@",error);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
