//
//  HttpManager.h
//  iVMS-8700-MCU
//
//  Created by apple on 15-3-16.
//  Copyright (c) 2015年 anran. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface HttpManager : NSObject

@property(nonatomic,copy)NSString *etag;

+(instancetype)shareHttpManager;

//https访问请求数据
-(void)post:(NSString *)url withParameters:(id)parameters success:(void (^)(NSURLSessionDataTask * _Nonnull task, id _Nullable responseObject))success failure:(void (^)(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error))failure;
//https下载
/**
 *  https下载请求
 *
 *  @param requestURLString 请求的urlString
 *  @param parameters       请求参数
 *  @param savedPath        下载文件保存路径
 *  @param success          下载成功回调
 *  @param failure          下载失败回调
 *  @param progress         下载进度描述
 */
- (void)downloadFileWithURL:(NSString*)requestURLString
                 parameters:(NSDictionary *)parameters
                  savedPath:(NSString*)savedPath
            downloadSuccess:(void (^)(NSURLResponse *response, NSURL *filePath))success
            downloadFailure:(void (^)(NSError *error))failure
           downloadProgress:(void (^)(NSProgress *downloadProgress))progress;

@end
