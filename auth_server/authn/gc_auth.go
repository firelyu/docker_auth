/*
   Copyright 2015 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package authn

import (
//	"encoding/json"
	"strings"
	"github.com/golang/glog"
)

type GCRequirements struct {
	Password PasswordString `yaml:"password,omitempty" json:"password,omitempty"`
}

type gcUsersAuth struct {
	users map[string]*GCRequirements
}

func (r GCRequirements) String() string {
	return string(r.Password)
}

func NewGCUserAuth(users map[string]*GCRequirements) *gcUsersAuth {
	return &gcUsersAuth{users: users}
}

func (sua *gcUsersAuth) Authenticate(user string, password PasswordString) (bool, error) {
	glog.V(2).Infof("reqs %v", sua)
	reqs := sua.users[user]
	if reqs == nil {
		return false, NoMatch
	}
	if reqs.Password != "" {
		if strings.Compare(string(reqs.Password), string(password)) != 0 {
			return false, nil
		}
	}
	return true, nil
}

func (sua *gcUsersAuth) Stop() {
}

func (sua *gcUsersAuth) Name() string {
	return "gcuser"
}
