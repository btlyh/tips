# IOS gameCenter 第三方服务器用户验证

# erlang
erlang版本：otp23
  
### 1.根据官方文档，客户端会调用本地SDK函数生成如下参数：
**PublicKeyURL**  
**PlayerID**  
**BundleID**  
**Timestamp**  
**Signature**  
**Salt**  

客户端在登录时上传上述参数至第三方服务器进行验签

[官方文档](https://developer.apple.com/documentation/gamekit/gklocalplayer/1515407-generateidentityverificationsign#discussion)

**PublicKeyURL**是一个url地址，用来获取当前公钥证书  
Signature和Salt需要进行base64解码  

### 2.代码示例
```erlang
%% IOS gameCenter 验签
verify(PublicKeyURL, PlayerID, BundleID, Timestamp, Signature, Salt) ->
	try
		inets:start(),
		ssl:start(),
		%% 获取证书数据
		{ok, {_, _, Data}} = httpc:request(PublicKeyURL),
		%% 由于获取的证书数据不是格式化好的，所以直接组装证书数据记录
		Entry = public_key:pem_entry_decode({'Certificate', list_to_binary(Data), not_encrypted}),
		{_, TBSCertificate, _, _} = Entry,
		SubjectPublicKeyInfo = lists:keyfind('SubjectPublicKeyInfo', 1, tuple_to_list(TBSCertificate)),
		{_, _, PublicKeyBin} = SubjectPublicKeyInfo,
		%% 组装公钥数据记录
		RSAPublicKey = public_key:der_decode('RSAPublicKey', PublicKeyBin),
		%% 将时间转成64位大端字节序列
		TimestampI = list_to_integer(Timestamp),
		TimestampBytes = <<TimestampI:64/unsigned-big-integer>>,
		%% 拼接验签数据,Salt参数进行base64解码
		DataBin = list_to_binary([list_to_binary(PlayerID), list_to_binary(BundleID), TimestampBytes, base64:decode(Salt)]),
		%% 进行验签,Signature参数进行base64解码
		public_key:verify(DataBin, sha256, base64:decode(Signature), RSAPublicKey)
	catch
		Err:Reason:Stack ->
			io:format("verify fail,Err = ~p~n, Reason = ~p~n,Stack = ~p~n", [Err, Reason, Stack])
	end.
  ```
