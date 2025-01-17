package service

import (
	"fmt"
	//	"net/url"
	"user_system/internal/cache"
	"user_system/internal/dao"
	"user_system/internal/model"
	"user_system/pkg/constant"
	"user_system/utils"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

// Register 用户注册
func Register(req *RegisterRequest) error {
	if req.UserName == "" || req.Password == "" || req.Age <= 0 || !utils.Contains([]string{constant.GenderMale, constant.GenderFeMale}, req.Gender) {
		log.Errorf("register param invalid")
		return fmt.Errorf("register param invalid")
	}
	existedUser, err := dao.GetUserByName(req.UserName)
	if err != nil {
		log.Errorf("Register|%v", err)
		return fmt.Errorf("register|%v", err)
	}
	if existedUser != nil {
		log.Errorf("用户已经注册,user_name==%s", req.UserName)
		return fmt.Errorf("用户已经注册，不能重复注册")
	}

	user := &model.User{
		Name:     req.UserName,
		Age:      req.Age,
		Gender:   req.Gender,
		PassWord: req.Password,
		NickName: req.NickName,
		CreateModel: model.CreateModel{
			Creator: req.UserName,
		},
		ModifyModel: model.ModifyModel{
			Modifier: req.UserName,
		},
	}
	log.Infof("user ====== %+v", user)
	if err := dao.CreateUser(user); err != nil {
		log.Errorf("Register|%v", err)
		return fmt.Errorf("register|%v", err)
	}
	return nil
}

// Login 用户登陆
func Login(ctx context.Context, req *LoginRequest) (string, error) {
	uuid := ctx.Value(constant.ReqUuid)
	log.Debugf(" %s| Login access from:%s,@,%s", uuid, req.UserName, req.PassWord)

	user, err := getUserInfo(req.UserName)
	if err != nil {
		log.Errorf("Login|%v", err)
		return "", fmt.Errorf("login|%v", err)
	}

	// 用户存在
	if req.PassWord != user.PassWord {
		log.Errorf("Login|password err: req.password=%s|user.password=%s", req.PassWord, user.PassWord)
		return "", fmt.Errorf("password is not correct")
	}

	session := utils.GenerateSession(user.Name)
	err = cache.SetSessionInfo(user, session)

	if err != nil {
		log.Errorf(" Login|Failed to SetSessionInfo, uuid=%s|user_name=%s|session=%s|err=%v", uuid, user.Name, session, err)
		return "", fmt.Errorf("login|SetSessionInfo fail:%v", err)
	}

	log.Infof("Login successfully, %s@%s with redis_session session_%s", req.UserName, req.PassWord, session)
	return session, nil
}

// Logout 退出登陆
func Logout(ctx context.Context, req *LogoutRequest) error {
	uuid := ctx.Value(constant.ReqUuid)
	session := ctx.Value(constant.SessionKey).(string)
	log.Infof("%s|Logout access from,user_name=%s|session=%s", uuid, req.UserName, session)
	// 要退出登录，必须要是在登录态
	_, err := cache.GetSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to get with session=%s|err =%v", uuid, session, err)
		return fmt.Errorf("Logout|GetSessionInfo err:%v", err)
	}

	err = cache.DelSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to delSessionInfo :%s", uuid, session)
		return fmt.Errorf("del session err:%v", err)
	}
	log.Infof("%s|Success to delSessionInfo :%s", uuid, session)
	return nil
}

// GetUserInfo 获取用户信息请求，只能在用户登陆的情况下使用
func GetUserInfo(ctx context.Context, req *GetUserInfoRequest) (*GetUserInfoResponse, error) {
	uuid := ctx.Value(constant.ReqUuid)
	session := ctx.Value(constant.SessionKey).(string)
	log.Infof("%s|GetUserInfo access from,user_name=%s|session=%s", uuid, req.UserName, session)

	if session == "" || req.UserName == "" {
		return nil, fmt.Errorf("GetUserInfo|request params invalid")
	}

	user, err := cache.GetSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to get with session=%s|err =%v", uuid, session, err)
		return nil, fmt.Errorf("getUserInfo|GetSessionInfo err:%v", err)
	}

	if user.Name != req.UserName {
		log.Errorf("%s|session info not match with username=%s", uuid, req.UserName)
	}
	log.Infof("%s|Succ to GetUserInfo|user_name=%s|session=%s", uuid, req.UserName, session)
	nickhead := "/images/Head.jpg"
	return &GetUserInfoResponse{
		UserName: user.Name,
		Age:      user.Age,
		Gender:   user.Gender,
		PassWord: user.PassWord,
		NickName: user.NickName,
		NickHead: nickhead,
	}, nil
}
func DeleteUser(ctx context.Context, req *LogoutRequest) error {
	fmt.Printf("call delete name....")
	uuid := ctx.Value(constant.ReqUuid)
	session := ctx.Value(constant.SessionKey).(string)
	log.Infof("%s|DeleteUserInfo access from,user_name=%s|session=%s", uuid, req.UserName, session)
	log.Infof("DeleteUserInfo|req==%v", req)

	user, err := cache.GetSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to get with session=%s|err =%v", uuid, session, err)
		return fmt.Errorf("DeleteUserInfo|GetSessionInfo err:%v", err)
	}

	if err = dao.DeleteUserInfo(user); err != nil {
		log.Errorf("Delete|%v", err)
		return fmt.Errorf("delete|%v", err)
	}
	err = cache.DelSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to delSessionInfo :%s", uuid, session)
		return fmt.Errorf("del session err:%v", err)
	}
	log.Infof("%s|Success to delSessionInfo :%s", uuid, session)

	return nil
}

func UpdateUserNickName(ctx context.Context, req *UpdateNickNameRequest) error {
	fmt.Printf("call name....")
	uuid := ctx.Value(constant.ReqUuid)
	session := ctx.Value(constant.SessionKey).(string)
	log.Infof("%s|UpdateUserNickName access from,user_name=%s|session=%s", uuid, req.UserName, session)
	log.Infof("UpdateUserNickName|req==%v", req)

	if session == "" || req.UserName == "" {
		return fmt.Errorf("UpdateUserNickName|request params invalid")
	}

	user, err := cache.GetSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to get with session=%s|err =%v", uuid, session, err)
		return fmt.Errorf("UpdateUserNickName|GetSessionInfo err:%v", err)
	}

	if user.Name != req.UserName {
		log.Errorf("UpdateUserNickName|%s|session info not match with username=%s", uuid, req.UserName)
	}

	updateUser := &model.User{
		NickName: req.NewNickName,
	}

	return updateUserInfo(updateUser, req.UserName, session)
}

func getUserInfo(userName string) (*model.User, error) {
	user, err := cache.GetUserInfoFromCache(userName)
	if err == nil && user.Name == userName {
		log.Infof("cache_user ======= %v", user)
		return user, nil
	}

	user, err = dao.GetUserByName(userName)
	if err != nil {
		return user, err
	}

	if user == nil {
		return nil, fmt.Errorf("用户尚未注册")
	}
	log.Infof("user === %+v", user)
	err = cache.SetUserCacheInfo(user)
	if err != nil {
		log.Error("cache userinfo failed for user:", user.Name, " with err:", err.Error())
	}
	log.Infof("getUserInfo successfully, with key userinfo_%s", user.Name)
	return user, nil
}

func updateUserInfo(user *model.User, userName, session string) error {
	affectedRows := dao.UpdateUserInfo(userName, user)

	// db更新成功
	if affectedRows == 1 {
		user, err := dao.GetUserByName(userName)
		if err == nil {
			cache.UpdateCachedUserInfo(user)
			if session != "" {
				err = cache.SetSessionInfo(user, session)
				if err != nil {
					log.Error("update session failed:", err.Error())
					cache.DelSessionInfo(session)
				}
			}
		} else {
			log.Error("Failed to get dbUserInfo for cache, username=%s with err:", userName, err.Error())
		}
	}
	return nil
}

// 更新用户图片 处理流，不走数据库应该不用。
// func UpdateUserNickImage(ctx context.Context, req string) error {
// 	fmt.Printf("call img....")
// 	uuid := ctx.Value(constant.ReqUuid)
// 	session := ctx.Value(constant.SessionKey).(string)
// 	log.Infof("%s|UpdateUserNickIMage access from,user_name=%s|session=%s", uuid, req, session)
// 	log.Infof("UpdateUserNickImage|req==%v", req)

// 	if session == "" || req == "" {
// 		return fmt.Errorf("UpdateUserNickName|request params invalid")
// 	}

// 	user, err := cache.GetSessionInfo(session)
// 	if err != nil {
// 		log.Errorf("%s|Failed to get with session=%s|err =%v", uuid, session, err)
// 		return fmt.Errorf("UpdateUserNickName|GetSessionInfo err:%v", err)
// 	}

// 	// // if req.NewHead != nil {
// 	// // 	log.Errorf("UpdateUserNickName|%s|session info not match with username=%s", uuid, req.UserName)
// 	// // }

// 	// // updateUser := &model.User{
// 	// // 	NickName: user.Name,
// 	// // }

// 	// return updateUserInfo(updateUser, req, session)
// 	return fmt.Errorf("UpdateUserNickName|request params invalid%v", user)
// }
