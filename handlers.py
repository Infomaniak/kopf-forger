# -*- coding: utf-8 -*-
"""
    kopf-forger
"""
import logging
from typing import Any, Callable, Dict, MutableMapping, Tuple

import kopf
import kubernetes
from kopf import Body, Diff, ObjectLogger, Spec
from kubernetes.client import ApiTypeError
from kubernetes.dynamic import Resource
from kubernetes.dynamic.exceptions import NotFoundError
from kubernetes.utils import FailToCreateError

APIForgeCallable = Callable[[Resource, str, str, dict, ObjectLogger, Any, Any], None]


def get_kind_name(manifest: Dict) -> Tuple[str, str]:
    """
    Builds a tuple (kind, name) for the input manifest.
    :param manifest: the resource manifest
    :return:
    """
    return manifest.get("kind"), manifest.get("metadata", {}).get("name")


def nullify_deleted_keys(old: MutableMapping, new: MutableMapping) -> MutableMapping:
    """
    Match an *old* and a *new* MutableMapping instances and adds the keys that
    exist in *old* but were removed in the *new* MutableMapping. All the keys
    missing from the *new* MutableMapping are added to it with None value.

    The nullify_deleted_keys function is recursive.

    >>> _old = {"x": 123, "y": {"z": 456}}
    >>> _new = {"x": 1234}
    >>> nullify_deleted_keys(_old, _new) == {"x": 1234, "y": None}
    True
    >>> _old = {"v": 123, "w": {"x": 456, "y": 789}}
    >>> _new = {"v": 1234, "w": {"x": 4567}}
    >>> nullify_deleted_keys(_old, _new) == \
    {"v": 1234, "w": {"x": 4567, "y": None}}
    True

    :param old: the old manifest which might have deleted keys
    :param new: the new manifest where missing keys are added with null value
    :return: the result mapping with no missing keys
    """
    for key, old_value in old.items():
        logging.debug(f"processing {key}={old_value} {type(old_value)}")
        if key not in new:
            new[key] = None
            logging.debug(f"Added {key}=None to {new}")
            continue

        if isinstance(old_value, MutableMapping):
            new_value = new.get(key, None)
            if isinstance(new_value, MutableMapping):
                logging.debug(f"Recursive call made on {key}")
                new[key] = nullify_deleted_keys(old_value, new_value)
            else:
                logging.warning(
                    f"Cannot apply nullify_deleted_keys to {new_value}"
                    f" {type(new_value)}"
                )
    return new


@kopf.on.create(group="infomaniak.com", kind="ResourceForger")
def create_handler(spec: Spec, name: str, logger: ObjectLogger, **kw) -> None:
    """
    The registered handler for resource creation. a curried version of forge
    with inner function create.
    :param spec: the kopf Spec
    :param name: the ResourceForger name
    :param logger: logger instance
    :param kw: other keyword arguments
    """
    kind = kw.get("body", {}).get("kind", None)
    return forge(create, spec, name, kind, logger, **kw)


@kopf.on.delete(group="infomaniak.com", kind="ResourceForger")
def delete_handler(spec: Spec, name: str, logger: ObjectLogger, **kw) -> None:
    """
    The registered handler for resource deletion, a curried version of forge
    with inner function delete.
    :param spec: the kopf Spec
    :param name: the ResourceForger name
    :param logger: logger instance
    :param kw: other keyword arguments
    """
    kind = kw.get("body", {}).get("kind", None)
    return forge(delete, spec, name, kind, logger, **kw)


def patch_handler(spec: Spec, name: str, logger: ObjectLogger, **kw) -> None:
    """
    A curried version of forge with inner function path. No handler registered.
    :param spec: the kopf Spec
    :param name: the ResourceForger name
    :param logger: logger instance
    :param kw: other keyword arguments
    """
    kind = kw.get("body", {}).get("kind", None)
    return forge(patch, spec, name, kind, logger, **kw)


@kopf.on.field(
    group="infomaniak.com",
    kind="ResourceForger",
    field="spec.targetNamespaces",
)
def update_target_namespaces(diff: Diff, spec: Spec, name: str, **kwargs) -> None:
    """
    The registered handler for updates on field spec.targetNamespaces.
    :param diff: the diff (operator, field, old manifest, new manifest)
    :param spec: the kopf Spec
    :param name: the ResourceForger name
    :param kwargs: other keyword arguments
    """
    resources = spec.get("originalResources", [])
    operator, _, old, new = diff[0]
    if operator == "add":
        logging.debug(f"Nothing done with diff: {diff[0]}")
        return
    old = old if old else []
    new = new if new else []
    changes = set(old) ^ set(new)
    creations = [ns for ns in changes if ns in new]
    if creations:
        create_handler(
            spec={
                "targetNamespaces": creations,
                "originalResources": resources,
            },
            name=name,
            **kwargs,
        )
    deletions = [ns for ns in changes if ns in old]
    if deletions:
        delete_handler(
            spec={
                "targetNamespaces": deletions,
                "originalResources": resources,
            },
            name=name,
            **kwargs,
        )


@kopf.on.field(
    group="infomaniak.com",
    kind="ResourceForger",
    field="spec.originalResources",
)
def update_original_resources(diff: Diff, spec: Spec, name: str, **kwargs) -> None:
    """
    The registered handler for field spec.originalResources update.
    :param diff: the diff (operator, field, old manifest, new manifest)
    :param spec: the kopf Spec
    :param name: the ResourceForger name
    :param kwargs: other keyword arguments
    """
    operator, _, old, new = diff[0]
    if operator == "add":
        logging.debug(f"Nothing done with diff: {diff[0]}")
        return
    old = {get_kind_name(m): m for m in old} if old else {}
    new = {get_kind_name(m): m for m in new} if new else {}
    changes = old.keys() ^ new.keys()
    deletions = [old[m] for m in changes if m in old]
    # Delete the resources that have been forged and then removed from
    # originalResources.
    if deletions:
        delete_handler(
            spec={
                "targetNamespaces": spec.get("targetNamespaces", []),
                "originalResources": deletions,
            },
            name=name,
            **kwargs,
        )
    # Create (forge) the resources added the originalResources.
    creations = [new[m] for m in changes if m in new]
    if creations:
        create_handler(
            spec={
                "targetNamespaces": spec.get("targetNamespaces", []),
                "originalResources": creations,
            },
            name=name,
            **kwargs,
        )
    # Patch the others resources that aren't either created or deleted.
    patches = [nullify_deleted_keys(old[m], new[m]) for m in old.keys() & new.keys()]
    if patches:
        patch_handler(
            spec=Spec(
                Body(
                    {
                        "spec": {
                            "targetNamespaces": spec.get("targetNamespaces", []),
                            "originalResources": patches,
                        }
                    }
                )
            ),
            name=name,
            **kwargs,
        )


def forge(
    api_inner_function: APIForgeCallable,
    spec: Spec,
    name: str,
    kind: str,
    logger: ObjectLogger,
    uid: str,
    **kw,
) -> None:
    """
    The core function to be used once curried with the right inner function.

    :param api_inner_function: a Callable (eg: create, delete, patch) see below
    :param spec: the kopf Spec
    :param name: the ResourceForger name
    :param kind: the ResourceForger kind
    :param logger: logger instance
    :param uid: the ResourceForger uid
    :param kw: other keyword arguments
    """
    resources = spec.get("originalResources", [])
    namespaces = spec.get("targetNamespaces", [])
    dynamic_client = kubernetes.dynamic.DynamicClient(
        kubernetes.client.api_client.ApiClient()
    )
    logger.debug(
        f"{name} will {api_inner_function.__name__} {len(resources)} resource"
        f"{'s' if len(resources) else ''}."
    )
    for namespace in namespaces:
        for manifest in resources:
            api_version = manifest.get("apiVersion")
            target_kind = manifest.get("kind")
            resource_name = manifest.get("metadata").get("name")
            crd_api = dynamic_client.resources.get(
                api_version=api_version, kind=target_kind
            )
            logger.info(
                f"{api_inner_function.__name__}-ing the {target_kind}: {resource_name} "
                f"in namespace {namespace}"
            )
            try:
                api_inner_function(
                    crd_api,
                    namespace,
                    resource_name,
                    manifest,
                    logger,
                    kind,
                    uid,
                )
            except (FailToCreateError, ApiTypeError) as err:
                logger.exception(
                    f"Failed to create the {target_kind} : {resource_name} in"
                    f" {namespace} raised {type(err).__name__}"
                )

    logger.info(f"{name} has terminated")


def create(
    crd_api: Resource,
    namespace: str,
    resource_name: str,
    manifest: dict,
    logger: ObjectLogger,
    kind: str,
    uid: str,
    *a,
    **kw,
) -> None:
    """
    Inner function to use in the forge() function to create a resource.

    :param crd_api: kubernetes API object
    :param namespace: the namespace
    :param resource_name: the CRD
    :param manifest: the resource definition
    :param logger: kopf logger
    :param kind: the kind of the resource forger CRD
    :param uid: the resource forger CRD identifier
    :param a: positional args
    :param kw: keyword args
    """
    try:
        crd_api.get(namespace=namespace, name=resource_name)
        logger.warning(
            f"{kind}: {resource_name} does already exist in namespace "
            f"{namespace}, skipping creation."
        )
    except NotFoundError:
        labels = manifest["metadata"].get("labels", {})
        labels.update(
            {
                "createdByKind": kind,
                "createdByUID": uid,
            }
        )
        manifest["metadata"]["labels"] = labels
        crd_api.create(body=manifest, namespace=namespace, name=resource_name)


def delete(
    crd_api: Resource,
    namespace: str,
    resource_name: str,
    manifest: dict,
    logger: ObjectLogger,
    *a,
    **kw,
) -> None:
    """
    Inner function to use in the forge() function to delete a resource.

    :param crd_api: kubernetes API object
    :param namespace: the namespace
    :param resource_name: the CRD
    :param manifest: the resource definition
    :param logger: kopf logger
    :param a: positional args
    :param kw: keyword args
    """
    try:
        crd_api.get(namespace=namespace, name=resource_name)
        crd_api.delete(resource_name, namespace=namespace)
    except NotFoundError:
        kind = manifest.get("kind")
        logger.warning(
            f"{kind}: {resource_name} does not exist in namespace "
            f"{namespace}, skipping deletion."
        )


def patch(
    crd_api: Resource,
    namespace: str,
    resource_name: str,
    manifest: dict,
    logger: ObjectLogger,
    *a,
    **kw,
) -> None:
    """
    Inner function to use in the forge() function to path a resource.

    :param crd_api: kubernetes API object
    :param namespace: the namespace
    :param resource_name: the CRD
    :param manifest: the resource definition
    :param logger: kopf logger
    :param a: positional args
    :param kw: keyword args
    """
    try:
        crd_api.get(namespace=namespace, name=resource_name)
        crd_api.patch(
            body=manifest,
            namespace=namespace,
            content_type="application/merge-patch+json",
        )
    except NotFoundError:
        kind = manifest.get("kind")
        logger.warning(
            f"{kind}: {resource_name} does not exist in namespace "
            f"{namespace}, skipping patch."
        )
