// Copyright (C) 2014-2018 Goodrain Co., Ltd.
// RAINBOND, Application Management Platform

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version. For any non-GPL usage of Rainbond,
// one or multiple Commercial Licenses authorized by Goodrain Co., Ltd.
// must be obtained first.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package handler

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/goodrain/rainbond/api/model"
	api_model "github.com/goodrain/rainbond/api/model"
	"github.com/goodrain/rainbond/db"
	dbmodel "github.com/goodrain/rainbond/db/model"
	eventdb "github.com/goodrain/rainbond/eventlog/db"
	"github.com/goodrain/rainbond/util/constants"
	"github.com/goodrain/rainbond/worker/master/podevent"
)

//LogAction  log action struct
type LogAction struct {
	EtcdCli *clientv3.Client
	eventdb *eventdb.EventFilePlugin
}

//CreateLogManager get log manager
func CreateLogManager(cli *clientv3.Client) *LogAction {
	return &LogAction{
		EtcdCli: cli,
		eventdb: &eventdb.EventFilePlugin{
			HomePath: "/grdata/logs/",
		},
	}
}

// GetEvents get target logs
func (l *LogAction) GetEvents(target, targetID string, page, size int) ([]*dbmodel.ServiceEvent, int, error) {
	if target == "tenant" {
		return db.GetManager().ServiceEventDao().GetEventsByTenantID(targetID, (page-1)*size, size)
	}
	return db.GetManager().ServiceEventDao().GetEventsByTarget(target, targetID, (page-1)*size, size)
}

// GetLatestExceptionEvents get the latest exception events
func (l *LogAction) GetLatestExceptionEvents(interval int) ([]*model.PodExceptionEvent, error) {
	createTime := time.Now().Add(time.Second * time.Duration(interval) * (-1))
	eventTypes := podevent.GetEventTypes()
	events, err := db.GetManager().ServiceEventDao().GetExceptionEventsByTime(eventTypes, createTime)
	if err != nil {
		return nil, err
	}
	var serviceIDs []string
	for _, event := range events {
		if event.ServiceID == "" {
			continue
		}
		serviceIDs = append(serviceIDs, event.ServiceID)
	}

	services, err := db.GetManager().TenantServiceDao().GetServiceByIDs(serviceIDs)
	if err != nil {
		return nil, err
	}
	componentAppRels := make(map[string]string)
	for _, service := range services {
		componentAppRels[service.ServiceID] = service.AppID
	}

	var podExceptionEvents []*model.PodExceptionEvent
	for _, event := range events {
		if event.ServiceID == "" {
			continue
		}
		counts := db.GetManager().ServiceEventDao().CountEvents(event.TenantID, event.ServiceID, event.OptType)
		podExceptionEvents = append(podExceptionEvents, &model.PodExceptionEvent{
			EventType:   event.OptType,
			EventNums:   counts,
			TenantID:    event.TenantID,
			AppID:       componentAppRels[event.ServiceID],
			ComponentID: event.ServiceID,
		})
	}
	return podExceptionEvents, nil
}

// GetEvents get target logs
func (l *LogAction) GetMyTeamsEvents(target string, targetIDs []string, page, size int) ([]*dbmodel.ServiceEvent, int, error) {
	if target == "tenant" {
		return db.GetManager().ServiceEventDao().GetEventsByTenantIDs(targetIDs, (page-1)*size, size)
	}
	return nil, 0, nil
}

//GetLogList get log list
func (l *LogAction) GetLogList(serviceAlias string) ([]*model.HistoryLogFile, error) {
	logDIR := path.Join(constants.GrdataLogPath, serviceAlias)
	_, err := os.Stat(logDIR)
	if os.IsNotExist(err) {
		return nil, err
	}
	fileList, err := ioutil.ReadDir(logDIR)
	if err != nil {
		return nil, err
	}

	var logFiles []*model.HistoryLogFile
	for _, file := range fileList {
		logfile := &model.HistoryLogFile{
			Filename:     file.Name(),
			RelativePath: path.Join("logs", serviceAlias, file.Name()),
		}
		logFiles = append(logFiles, logfile)
	}
	return logFiles, nil
}

//GetLogFile GetLogFile
func (l *LogAction) GetLogFile(serviceAlias, fileName string) (string, string, error) {
	logPath := path.Join(constants.GrdataLogPath, serviceAlias)
	fullPath := path.Join(logPath, fileName)
	_, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		return "", "", err
	}
	return logPath, fullPath, err
}

//GetLogInstance get log web socket instance
func (l *LogAction) GetLogInstance(serviceID string) (string, error) {
	value, err := l.EtcdCli.Get(context.Background(), fmt.Sprintf("/event/dockerloginstacne/%s", serviceID))
	if err != nil {
		return "", err
	}

	if len(value.Kvs) > 0 {
		return string(value.Kvs[0].Value), nil
	}

	return "", nil
}

//GetLevelLog get event log
func (l *LogAction) GetLevelLog(eventID string, level string) (*api_model.DataLog, error) {
	re, err := l.eventdb.GetMessages(eventID, level, 0)
	if err != nil {
		return nil, err
	}
	if re != nil {
		messageList, ok := re.(eventdb.MessageDataList)
		if ok {
			return &api_model.DataLog{
				Status: "success",
				Data:   messageList,
			}, nil
		}
	}
	return &api_model.DataLog{
		Status: "success",
		Data:   nil,
	}, nil
}

//Decompress zlib解码
func decompress(zb []byte) ([]byte, error) {
	b := bytes.NewReader(zb)
	var out bytes.Buffer
	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(&out, r); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func checkLevel(level, info string) bool {
	switch level {
	case "error":
		if info == "error" {
			return true
		}
		return false
	case "info":
		if info == "info" || info == "error" {
			return true
		}
		return false
	case "debug":
		if info == "info" || info == "error" || info == "debug" {
			return true
		}
		return false
	default:
		if info == "info" || info == "error" {
			return true
		}
		return false
	}
}

func uncompress(source []byte) (re []byte, err error) {
	r, err := zlib.NewReader(bytes.NewReader(source))
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	io.Copy(&buffer, r)
	r.Close()
	return buffer.Bytes(), nil
}

func bubSort(d []api_model.MessageData) []api_model.MessageData {
	for i := 0; i < len(d); i++ {
		for j := i + 1; j < len(d); j++ {
			if d[i].Unixtime > d[j].Unixtime {
				temp := d[i]
				d[i] = d[j]
				d[j] = temp
			}
		}
	}
	return d
}
