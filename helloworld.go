/*

Copyright 2019 JamesJJ.

Function "InClusterConfig" modified from:
https://github.com/kubernetes/client-go/blob/e65ca70987a6941be583f205696e0b1b7da82002/rest/config.go
Copyright 2016 The Kubernetes Authors.

- - -

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package main

import (
	"encoding/json"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

type Config = rest.Config
type TLSClientConfig = rest.TLSClientConfig

type HTTPHeader = corev1.HTTPHeader

type MonitorableContainer struct {
	name                 string
	podName              string
	probeTargetPort      int
	probeTargetPath      string
	probeHeaders         []HTTPHeader
	initialDelaySeconds  int32
	runningStartedAtTime time.Time
}

type SuccessJSON struct {
	Container string `json:"container"`
	Pod       string `json:"pod"`
	Delay     int64  `json:"delay"`
	Info      string `json:"info"`
}

var (
	Debug            *log.Logger
	Info             *log.Logger
	Error            *log.Logger
	promReg          = prometheus.NewRegistry()
	appLivenessTimes = *prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "liveness_time_seconds",
			Help: "Time in seconds between app start and app alive",
		},
		[]string{"container_name", "pod_name"},
	)
)

func init() {
	promReg.MustRegister(appLivenessTimes)
}

func main() {

	LogInit()

	// Handle ^C and SIGTERM gracefully
	var gracefulStop = make(chan os.Signal)
	signal.Notify(gracefulStop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-gracefulStop
		Debug.Printf("Caught signal: %+v", sig)
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	// record our own start time
	startTime := time.Now()

	// Wait a little to ensure the all containers in this Pod
	// have been started)
	iWait, err := strconv.Atoi(os.Getenv("ASM_INITIAL_WAIT"))
	if iWait < 5 || e(err) {
		iWait = 5
	}
	Debug.Printf("Waiting for %d seconds . . .", iWait)
	time.Sleep(time.Duration(iWait) * time.Second)

	// get a list of containers running in this pod
	// that have liveness checks configured
	// and concurrently probe them for liveness
	for _, pcData := range getPodContainers() {
		go timePcLiveness(startTime, pcData, &appLivenessTimes)
	}

	// Prepare to handle /health requests to HTTP server
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		versionMap := map[string]string{"startTime": startTime.UTC().Format(time.UnixDate)}
		versionJSON, _ := json.Marshal(versionMap)
		fmt.Fprintf(w, string(versionJSON))
	})

	// Prepare to handle /metrics requests using prometheus library
	http.Handle("/metrics", promhttp.HandlerFor(promReg, promhttp.HandlerOpts{}))

	// Start HTTP server listener
	bindAddress := ":8888"
	if len(os.Getenv("ASM_BINDADDRESS")) > 0 {
		bindAddress = strings.ToLower(os.Getenv("ASM_BINDADDRESS"))
	}
	Debug.Printf("HTTP server binding to: %s", bindAddress)
	http.ListenAndServe(bindAddress, nil)

}

func LogInit() {

	errorHandle := os.Stderr
	infoHandle := os.Stdout

	debugHandle := ioutil.Discard
	if strings.ToLower(os.Getenv("ASM_VERBOSE")) == "true" {
		debugHandle = os.Stderr
	}

	Debug = log.New(debugHandle,
		"DEB: ",
		log.Ldate|log.Lmicroseconds|log.LUTC)

	Info = log.New(infoHandle,
		"INF: ",
		log.Ldate|log.Lmicroseconds|log.LUTC)

	Error = log.New(errorHandle,
		"ERR: ",
		log.Ldate|log.Lmicroseconds|log.LUTC)

	// no ocndition here, as you'll only see the message if
	// Verbose logging really is enabled!
	Debug.Printf("Verbose logging enabled")

}

// Identify directory containing our K8S service account token and CA cert
// This allows us to use K8S pod "serviceAccountName" setting, which gives
// permission to _all_ continaers in the pod, or use a secret volume mount
// which allows us to independently provide a service account to _this_
// container
func SecretsDirectory() (dir string) {
	dir, envExist := os.LookupEnv("ASM_SECRETS_DIR")
	if envExist != true {
		dir = "/var/run/secrets/serviceaccount"
	}
	dir = filepath.Clean(dir)
	s, err := os.Stat(dir)
	if err != nil {
		Error.Fatalf("Secrets directory error (%s): %v", dir, err)
	}
	if s.Mode().IsRegular() {
		Error.Fatalf("Secrets directory does not exist (%s)", dir)
	}
	Debug.Printf("Secrets directory is: %s", dir)
	return
}

// This is duplicated from "k8s.io/client-go/rest" with hardcoded secrets
// directory replaced with response from SecretsDirectory()
func InClusterConfig() *Config {
	sdir := SecretsDirectory()

	tokenFile := filepath.Join(sdir, "token")
	rootCAFile := filepath.Join(sdir, "ca.crt")

	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		Error.Fatalf("env KUBERNETES_SERVICE_HOST or KUBERNETES_SERVICE_PORT not set correctly (not running in-cluster??)")
	}
	Debug.Printf("KUBERNETES: %s:%s", host, port)

	token, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		Error.Fatalf("Failed to read K8S token file: %v", err)
	}

	tlsClientConfig := TLSClientConfig{}
	if _, err := certutil.NewPool(rootCAFile); err != nil {
		Error.Fatalf("Expected to load root CA config from %s, but got err: %v", rootCAFile, err)
	} else {
		tlsClientConfig.CAFile = rootCAFile
	}

	return &Config{
		Host:            "https://" + net.JoinHostPort(host, port),
		TLSClientConfig: tlsClientConfig,
		BearerToken:     string(token),
		BearerTokenFile: tokenFile,
	}
}

// Search the current pod for containers that are running, and have HTTP
// liveness probes configured
func getPodContainers() (MonitorableContainerList map[string]*MonitorableContainer) {

	MonitorableContainerList = make(map[string]*MonitorableContainer)

	pod_name, pod_namespace := os.Getenv("POD_NAME"), os.Getenv("POD_NAMESPACE")
	if len(pod_name) == 0 || len(pod_namespace) == 0 {
		Error.Fatalf("env POD_NAME or POD_NAMESPACE not set correctly")
	}
	Debug.Printf("Pod namespace / name: %s / %s", pod_namespace, pod_name)

	config := InClusterConfig()

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		Error.Fatalf(err.Error())
	}

	podList, err := clientset.CoreV1().Pods(pod_namespace).Get(pod_name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		Error.Fatalf("Pod %s in namespace %s not found\n", pod_name, pod_namespace)
	} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
		Error.Fatalf("Error getting pod %s in namespace %s: %v\n",
			pod_name, pod_namespace, statusError.ErrStatus.Message)
	} else if err != nil {
		Error.Fatalf(err.Error())
	} else {
		Debug.Printf("Found pod %s in namespace %s\n", pod_name, pod_namespace)

		for _, csc := range podList.Spec.Containers {
			if csc.LivenessProbe == nil {
				Debug.Printf("Skipping container without LivenessProbe: %s", csc.Name)
				continue
			}
			if csc.LivenessProbe.HTTPGet == nil {
				Debug.Printf("Skipping container without HTTP LivenessProbe: %s", csc.Name)
				continue
			}
			if len(csc.LivenessProbe.HTTPGet.Host) != 0 {
				Debug.Printf("Skipping container HTTP Host address hard set in LivenessProbe: %s", csc.Name)
				continue
			}

			if MonitorableContainerList[csc.Name] == nil {
				MonitorableContainerList[csc.Name] = &MonitorableContainer{}
			}

			MonitorableContainerList[csc.Name].name = csc.Name
			MonitorableContainerList[csc.Name].podName = pod_name
			MonitorableContainerList[csc.Name].probeTargetPort = csc.LivenessProbe.HTTPGet.Port.IntValue()
			MonitorableContainerList[csc.Name].probeTargetPath = csc.LivenessProbe.HTTPGet.Path
			MonitorableContainerList[csc.Name].probeHeaders = csc.LivenessProbe.HTTPGet.HTTPHeaders
			MonitorableContainerList[csc.Name].initialDelaySeconds = csc.LivenessProbe.InitialDelaySeconds

		}

		for _, cst := range podList.Status.ContainerStatuses {
			if MonitorableContainerList[cst.Name] == nil {
				continue
			}
			if cst.State.Running == nil {
				Error.Printf("Expected container to be in Running state: %s", cst.Name)
				continue
			}
			MonitorableContainerList[cst.Name].runningStartedAtTime = cst.State.Running.StartedAt.Time
			Debug.Printf("Will do startup timing for container: %s", cst.Name)
		}
	}
	return
}

// Probe the target container for liveness until it is alive or maxCheckPeriod is exceeded
func timePcLiveness(startTime time.Time, pc *MonitorableContainer, appLivenessTimes *prometheus.GaugeVec) {

	//log.Printf("%v\n", cst.State.Running.StartedAt)
	//log.Printf("%v\n", now.Sub(cst.State.Running.StartedAt.Time))
	//log.Printf("%v\n", (now.Sub(cst.State.Running.StartedAt.Time) > 10*time.Minute))
	Debug.Printf("Starting to probe container: %s", pc.name)
	Debug.Printf("Probe container details: %v", pc)

	containerStartTime := time.Now()
	if pc.runningStartedAtTime.IsZero() == false {
		containerStartTime = pc.runningStartedAtTime
	}
	Debug.Printf("Taking container %s start time as: %v (Approximated: %v)",
		pc.name, containerStartTime, pc.runningStartedAtTime.IsZero())

	maxCheckPeriod := 10 * time.Minute

	targetUrl := fmt.Sprintf("http://%s:%d%s", "localhost", pc.probeTargetPort, pc.probeTargetPath)
	Debug.Printf("Taking container %s target URL as: %s", pc.name, targetUrl)

	nowTime := time.Now()
	elaspedTime := nowTime.Sub(nowTime)
	for nowTime.Sub(startTime) < maxCheckPeriod {
		statusCode, statusInfo := HttpCheck(targetUrl)
		if statusInfo != nil {
			elaspedTime = nowTime.Sub(containerStartTime)
			Debug.Printf("Container %s success info: %v, %v", pc.name, *statusCode, *statusInfo)
			Debug.Printf("Container %s success time: %v (%s)", pc.name, nowTime, elaspedTime.String())
			appLivenessTimes.WithLabelValues(pc.name, pc.podName).Set(float64(elaspedTime.Seconds()))
			successMsg := &SuccessJSON{
				Container: pc.name,
				Pod:       pc.podName,
				Delay:     int64(elaspedTime.Seconds()),
				Info:      *statusInfo,
			}
			successJM, _ := json.Marshal(successMsg)
			Info.Printf("JSON: %s", successJM)
			break
		} else {
			Debug.Printf("Container %s HTTP status: %v", pc.name, *statusCode)
		}
		time.Sleep(2 * time.Second)
		nowTime = time.Now()
	}

}

func e(err error) bool {
	if err != nil {
		Error.Println(err)
		return true
	}
	return false
}

// Return a truncated, single line, with no leading or trailing whitespace
func maxString(s string, maxLen int, singleLineTrimWhitespace bool) string {

	if len(s) > maxLen {
		s = s[:maxLen]
	}
	for len(s) > maxLen || utf8.ValidString(s) == false {
		s = s[:len(s)-1] // remove a byte
	}
	if singleLineTrimWhitespace {
		re := regexp.MustCompile(`[\r\n]+`)
		s = strings.TrimSpace(re.ReplaceAllString(s, " "))
	}
	return s
}

// GET a url and return pointers to status code and a
//  truncated response body; or nil if timeout or failure
func HttpCheck(url string) (code *int, info *string) {
	defaultStatus := 0
	code = &defaultStatus
	info = nil

	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 2 * time.Second,
	}
	var netClient = &http.Client{
		Timeout:   time.Second * 2,
		Transport: netTransport,
	}

	resp, err := netClient.Get(url)
	if e(err) {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode > 0 {
		*code = resp.StatusCode
	}
	if *code != http.StatusOK {
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if e(err) {
		return
	}

	infoString := maxString(string(body), 128, true)
	info = &infoString

	return

}