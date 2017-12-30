load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = ["admission.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/client/clientset_generated/internalclientset:go_default_library",
        "//pkg/kubeapiserver/admission:go_default_library",
        "//plugin/pkg/admission/ucputil:go_default_library",
        "//vendor/github.com/docker/go-connections/tlsconfig:go_default_library",
        "//vendor/github.com/sirupsen/logrus:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/api/errors:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/apis/meta/v1:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/runtime:go_default_library",
        "//vendor/k8s.io/apiserver/pkg/admission:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = ["admission_test.go"],
    library = ":go_default_library",
    deps = [
        "//pkg/api:go_default_library",
        "//vendor/github.com/stretchr/testify/assert:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/apis/meta/v1:go_default_library",
        "//vendor/k8s.io/apiserver/pkg/admission:go_default_library",
        "//vendor/k8s.io/apiserver/pkg/authentication/user:go_default_library",
    ],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [":package-srcs"],
    tags = ["automanaged"],
    visibility = ["//visibility:public"],
)
