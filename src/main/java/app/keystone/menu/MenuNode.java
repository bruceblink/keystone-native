package app.keystone.menu;

import java.util.List;

public record MenuNode(Menu menu, List<MenuNode> children) {}
