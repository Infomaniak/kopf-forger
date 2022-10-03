# Kopf-forger

This CRD replicates arbitrary resource(s) in each of the target namespaces.
See the [example](#example-using-the-operator-to-forge-configmaps) section below.


## Deploy with kustomize and flux (recommended)

create a new overlay like staging.

If you are not using flux but only kustomize, create secret like first step then apply your overlay.

```bash
kustomize build ./deploy/overlays/${YOUR_OVERLAY} | k apply -f -
```

## Example using the operator to forge ConfigMaps

```yaml
---
apiVersion: infomaniak.com/v1
kind: ResourceForger
metadata:
  name: HansVanMeegeren
  namespace: default
spec:
  targetNamespaces:
    - francois-kawala
    - another-existing-name
  originalResources:
    - apiVersion: v1
      kind: ConfigMap
      metadata:
        name: example-config
      data:
        game.properties: |
          enemies=aliens
          lives=3
        ui.properties: |
          color.good=purple
```
To apply this CRD will trigger the creation of the **example-config**
ConfigMap in each namespace listed in **spec.targetNamespaces**. Additions,
deletions and updates of the **spec.targetNamespaces** **spec.
originalResources** fields will be reflected on dependent resources in each
target namespace. You can give it a try using the [example.yaml](example.yaml) file.

## Dev (python 3.8)

### Pipenv
Setup your dev environment
```bash
git clone https://github.com/Infomaniak/kopf-forger.git
cd ./kopf-forger
pipenv sync -d
precommit install
```

If you're using PyCharm check out
[DEVELOPMENT.md](https://github.com/zalando-incubator/kopf/blob/master/DEVELOPMENT.md#pycharm--ides) from Zalando Kopf
documentation. Be sure to correctly configure your KUBECONFIG environment variable in your IDE.

### setup a k8s cluster

```bash
k3d cluster create test-operator --kubeconfig-update-default=false
export KUBECONFIG=$(k3d kubeconfig write test-operator)
```

### install the crd in the cluster

```bash
kubectl apply -f deploy/bases/crd.yaml
```

### starting the operator

```bash
pipenv install --dev --pre
kopf run handlers.py --verbose --dev
```

### cleaning

```bash
k3d cluster delete test-operator
```
