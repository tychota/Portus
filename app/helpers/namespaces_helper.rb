module NamespacesHelper
  def can_manage_namespace?(namespace)
    current_user.admin? || owner?(namespace)
  end

  def owner?(namespace)
    namespace.team.owners.exists?(current_user.id)
  end

  def contributor?(namespace)
    namespace.team.contributors.exists?(current_user.id)
  end

  def viewer?(namespace)
    namespace.team.viewers.exists?(current_user.id)
  end

  def can_pull?(namespace)
    NamespacePolicy.new(current_user, namespace).pull?
  end

  def can_push?(namespace)
    NamespacePolicy.new(current_user, namespace).push?
  end
end
