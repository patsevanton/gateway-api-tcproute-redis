resource "yandex_kubernetes_cluster" "envoy-gateway" {
  name       = "envoy-gateway"
  network_id = yandex_vpc_network.k8s-network.id

  master {
    version = "1.33"
    zonal {
      zone      = yandex_vpc_subnet.k8s-subnet.zone
      subnet_id = yandex_vpc_subnet.k8s-subnet.id
    }
    public_ip          = true
  }

  service_account_id      = yandex_iam_service_account.sa-k8s-admin.id
  node_service_account_id = yandex_iam_service_account.sa-k8s-admin.id
  release_channel         = "RAPID"
  cluster_ipv4_range      = "10.114.0.0/16"
  service_ipv4_range      = "10.98.0.0/16"

  // Ensure the reserved public IP exists before the cluster is created, and on destroy
  // make Terraform delete the cluster first, then wait, then delete the IP.
  depends_on = [
    yandex_resourcemanager_folder_iam_member.sa-k8s-admin-permissions,
    time_sleep.wait_before_address_deletion,
  ]
}

resource "time_sleep" "wait_for_cluster_deletion" {
  depends_on = [
    yandex_kubernetes_cluster.envoy-gateway,
    yandex_kubernetes_node_group.k8s_node_group_envoy_gateway
  ]

  destroy_duration = "180s"
}

resource "yandex_kubernetes_node_group" "k8s_node_group_envoy_gateway" {
  cluster_id = yandex_kubernetes_cluster.envoy-gateway.id
  name       = "node-group-envoy-gateway"
  version    = "1.33"

  instance_template {
    platform_id = "standard-v3"

    network_interface {
      nat        = true
      subnet_ids = [yandex_vpc_subnet.k8s-subnet.id]
    }

    resources {
      cores  = 2
      memory = 8
    }

    boot_disk {
      type = "network-ssd"
      size = 65
    }

    metadata = {
      ssh-keys = "ubuntu:${file("~/.ssh/id_ed25519.pub")}"
    }

  }

  scale_policy {
    fixed_scale {
      size = 3
    }
  }

  allocation_policy {
    location {
      zone = "ru-central1-b"
    }
  }
}

resource "local_file" "envoyproxy_yaml" {
  content = templatefile("${path.module}/envoyproxy.yaml.tpl", {
    load_balancer_ip = yandex_vpc_address.addr.external_ipv4_address[0].address
  })
  filename = "${path.module}/envoyproxy.yaml"

  depends_on = [yandex_vpc_address.addr]
}


output "get_credentials_command_envoy_gateway" {
  description = "Command to get kubeconfig for the envoy-gateway cluster"
  value       = "yc managed-kubernetes cluster get-credentials --id ${yandex_kubernetes_cluster.envoy-gateway.id} --external --force"
}
