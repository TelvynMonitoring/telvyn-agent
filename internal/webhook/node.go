package webhook

import (
	"fmt"
	"strings"
)

// nodePatch installs the operator's package without changing the application command.
func nodePatch(pod podMeta, selected, image, endpoint string) ([]patchOp, error) {
	return runtimePatch(pod, selected, image, endpoint, "node", "NODE_OPTIONS", "--require=/opt/telvyn/node/register.cjs", " ", nil)
}

func pythonPatch(pod podMeta, selected, image, endpoint string) ([]patchOp, error) {
	return runtimePatch(pod, selected, image, endpoint, "python", "PYTHONPATH", "/opt/telvyn/python", ":", []envVar{
		{Name: "OTEL_PYTHON_DISTRO", Value: "telvyn"},
		{Name: "OTEL_TRACES_EXPORTER", Value: "telvyn"},
		{Name: "OTEL_METRICS_EXPORTER", Value: "none"},
		{Name: "OTEL_LOGS_EXPORTER", Value: "none"},
	})
}

func dotnetPatch(pod podMeta, selected, image, endpoint string) ([]patchOp, error) {
	return runtimePatch(pod, selected, image, endpoint, "dotnet", "DOTNET_ADDITIONAL_DEPS", "/opt/telvyn/dotnet/Telvyn.Agent.deps.json", ":", []envVar{
		{Name: "DOTNET_SHARED_STORE", Value: "/opt/telvyn/dotnet/store"},
		{Name: "ASPNETCORE_HOSTINGSTARTUPASSEMBLIES", Value: "Telvyn.Agent"},
	})
}

func rubyPatch(pod podMeta, selected, image, endpoint string) ([]patchOp, error) {
	return runtimePatch(pod, selected, image, endpoint, "ruby", "RUBYOPT", "-r/opt/telvyn/ruby/inject.rb", " ", nil)
}

func phpPatch(pod podMeta, selected, image, endpoint string) ([]patchOp, error) {
	// Empty scan-path entry preserves PHP's compiled default configuration directory.
	return runtimePatch(pod, selected, image, endpoint, "php", "PHP_INI_SCAN_DIR", "/opt/telvyn/php/injection:", ":", nil)
}

func runtimePatch(pod podMeta, selected, image, endpoint, language, optionsName, optionsValue, separator string, settings []envVar) ([]patchOp, error) {
	if image == "" {
		return nil, fmt.Errorf("%s agent image is not configured", language)
	}
	volumeName := "telvyn-" + language + "-agent"
	mountPath := "/opt/telvyn/" + language
	for _, v := range pod.Spec.Volumes {
		if v.Name == volumeName {
			return nil, fmt.Errorf("reserved volume already exists")
		}
	}
	for _, c := range pod.Spec.InitContainers {
		if c.Name == volumeName {
			return nil, fmt.Errorf("reserved init container already exists")
		}
	}
	targets := map[string]bool{}
	for _, name := range strings.Split(selected, ",") {
		name = strings.TrimSpace(name)
		if name == "" || targets[name] {
			return nil, fmt.Errorf("invalid container selection")
		}
		targets[name] = true
	}
	ops := []patchOp{}
	for idx, c := range pod.Spec.Containers {
		if !targets[c.Name] {
			continue
		}
		delete(targets, c.Name)
		if len(c.EnvFrom) > 0 {
			return nil, fmt.Errorf("container %s uses envFrom; configure instrumentation explicitly to preserve indirect settings", c.Name)
		}
		for _, m := range c.VolumeMounts {
			if m.Name == volumeName || m.MountPath == mountPath {
				return nil, fmt.Errorf("container %s has a conflicting mount", c.Name)
			}
		}
		envs := []envVar{}
		existing := map[string]bool{}
		for i, e := range c.Env {
			existing[e.Name] = true
			value, delimiter := optionsValue, separator
			merge := e.Name == optionsName
			if language == "dotnet" && e.Name == "DOTNET_SHARED_STORE" {
				merge, value, delimiter = true, mountPath+"/store", ":"
			}
			if language == "dotnet" && e.Name == "ASPNETCORE_HOSTINGSTARTUPASSEMBLIES" {
				merge, value, delimiter = true, "Telvyn.Agent", ";"
			}
			if merge {
				if e.ValueFrom != nil || strings.Contains(strings.ToLower(e.Value), "telvyn") {
					return nil, fmt.Errorf("container %s has managed or indirect %s", c.Name, optionsName)
				}
				merged := value
				if e.Value != "" {
					merged += delimiter + e.Value
				}
				ops = append(ops, patchOp{Op: "add", Path: containerPath(idx, "/env/"+itoa(i)+"/value"), Value: merged})
			}
		}
		defaults := []envVar{
			{Name: optionsName, Value: optionsValue},
			{Name: "NODE_IP", ValueFrom: fieldRef("status.hostIP")},
			{Name: "OTEL_EXPORTER_OTLP_ENDPOINT", Value: endpoint},
			{Name: "OTEL_EXPORTER_OTLP_PROTOCOL", Value: "http/protobuf"},
			{Name: "OTEL_SERVICE_NAME", Value: c.Name},
		}
		defaults = append(defaults, settings...)
		for _, e := range defaults {
			if !existing[e.Name] {
				envs = append(envs, e)
			}
		}
		if len(c.Env) == 0 {
			ops = append(ops, patchOp{Op: "add", Path: containerPath(idx, "/env"), Value: envs})
		} else {
			for _, e := range envs {
				ops = append(ops, patchOp{Op: "add", Path: containerPath(idx, "/env/-"), Value: e})
			}
		}
		mount := volumeMount{Name: volumeName, MountPath: mountPath, ReadOnly: true}
		if len(c.VolumeMounts) == 0 {
			ops = append(ops, patchOp{Op: "add", Path: containerPath(idx, "/volumeMounts"), Value: []volumeMount{mount}})
		} else {
			ops = append(ops, patchOp{Op: "add", Path: containerPath(idx, "/volumeMounts/-"), Value: mount})
		}
	}
	if len(targets) > 0 {
		return nil, fmt.Errorf("selected container does not exist")
	}
	v := volume{Name: volumeName, EmptyDir: map[string]interface{}{}}
	if len(pod.Spec.Volumes) == 0 {
		ops = append(ops, patchOp{Op: "add", Path: "/spec/volumes", Value: []volume{v}})
	} else {
		ops = append(ops, patchOp{Op: "add", Path: "/spec/volumes/-", Value: v})
	}
	init := map[string]interface{}{
		"name": volumeName, "image": image, "imagePullPolicy": "IfNotPresent",
		"command":      []string{"sh", "-c", "cp -R " + mountPath + "/. /target/"},
		"volumeMounts": []volumeMount{{Name: volumeName, MountPath: "/target"}},
		"resources": map[string]interface{}{
			"requests": map[string]string{"cpu": "10m", "memory": "16Mi"},
			"limits":   map[string]string{"cpu": "100m", "memory": "64Mi"},
		},
	}
	if len(pod.Spec.InitContainers) == 0 {
		ops = append(ops, patchOp{Op: "add", Path: "/spec/initContainers", Value: []interface{}{init}})
	} else {
		ops = append(ops, patchOp{Op: "add", Path: "/spec/initContainers/-", Value: init})
	}
	return ops, nil
}
